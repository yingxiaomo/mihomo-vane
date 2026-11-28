package outboundgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// VERIFY-STALL-GRACE: a recently-fast graced low window says nothing about the
// node the flow just landed on — the client was reading fast 30 seconds ago —
// so it must not trigger the landing penalty. Synthetic silence still does
// (existing VERIFY-STALL coverage pins that side).
func TestVaneGracedLowsDoNotPenalizeLanding(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchLive)
	key := group.targetScopeKey(flow.target, flow.port)
	now := clock.Now()
	group.mu.Lock()
	group.ledger[key] = vaneSwitchLedger{verifyNode: flow.candidate, verifyAt: now, windowFrom: now, count: 1}
	group.mu.Unlock()

	fast := vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Duration: 4 * time.Second, Age: 20 * time.Second}
	require.Nil(t, flow.observe(fast))
	for i := 0; i < 2; i++ {
		clock.Advance(5 * time.Second)
		low := vaneObservationLowSample()
		low.Duration = 4 * time.Second
		require.Nil(t, flow.observe(low))
	}
	require.Zero(t, countVaneEvents(group, "verify-penalty", ""),
		"a recently-fast graced landing must not cool the node")
	group.mu.Lock()
	cooling := group.nodeCoolingLocked(flow.candidate, clock.Now())
	group.mu.Unlock()
	require.False(t, cooling, "the landing node stays eligible")
}

// STICKY-SWEEP: sticky entries expire after one TTL, but the only prune points
// sit on reconnect paths — the write path must sweep them itself, or the map
// grows with every distinct host ever dialed until a stall happens to prune.
func TestVaneStickySweepExpiresWithoutReconnect(t *testing.T) {
	group, clock, alpha, _, _ := newTargetGroupForTest(t)
	now := clock.Now()
	group.mu.Lock()
	defer group.mu.Unlock()
	for i := 0; i < 8; i++ {
		group.rememberStickyLocked(fmt.Sprintf("host-%d.example.com", i), 443, alpha.Name(), now)
	}
	group.rememberStickyLocked("host-9.example.com", 443, alpha.Name(), now)
	require.Len(t, group.stickiness, 9, "no sweep inside the interval")

	later := now.Add(vaneStickyTTL + vaneStickySweepInterval)
	group.rememberStickyLocked("host-0.example.com", 443, alpha.Name(), later)
	require.Len(t, group.stickiness, 1, "expired stickies are swept by the write path alone")
}

// AUDIT-2026-11-28 opt-in fixes: a broken collector must degrade (native
// events off), not fail the whole config apply; orphan event directories get
// swept on activation; rotated files are bounded; a stuck release cannot hold
// the config mux forever.
func TestVaneNativeCollectorFailureDegradesActivation(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(blocked, []byte("file"), 0o600))
	// Built directly: the constructor would reject the non-home path before
	// the acquire could exercise its own directory failure.
	spec := &vaneNativeCollectorSpec{directory: blocked, queueSize: 8, maxFileSize: 1 << 20, maxFileAge: time.Minute, flushInterval: 5 * time.Second}
	_, err := acquireVaneNativeCollector(spec)
	require.Error(t, err, "a file in place of the directory must fail the acquire")

	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	group.collectorSpec = spec
	batch := PrepareVaneLearningStates(map[string]C.Proxy{"vane": A.NewProxy(group)})
	require.NoError(t, batch.Err(), "the activation must not fail on a broken collector")
	require.Len(t, batch.entries, 1)
	require.Nil(t, batch.entries[0].collector, "the group runs with events disabled")
	require.NotNil(t, batch.entries[0].owner, "learning activation is unaffected")
	batch.Commit()
	group.Close()
}

func TestVaneNativeSweepRemovesOrphanDirsOnly(t *testing.T) {
	parent := t.TempDir()
	live := filepath.Join(parent, "g-live")
	orphan := filepath.Join(parent, "g-orphan")
	foreign := filepath.Join(parent, "unrelated")
	for _, dir := range []string{live, orphan, foreign} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	sweepVaneNativeOrphanDirs(parent, map[string]struct{}{live: {}})
	_, err := os.Stat(live)
	require.NoError(t, err, "the live directory stays")
	_, err = os.Stat(orphan)
	require.True(t, os.IsNotExist(err), "the orphan directory is removed")
	_, err = os.Stat(foreign)
	require.NoError(t, err, "non g-* directories are never touched")
}

func TestVaneNativeRotatedFilesAreBounded(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < vaneNativeRetainedFiles+4; i++ {
		name := filepath.Join(dir, fmt.Sprintf("vane-native-v1.run.%d.%d.jsonl.ready", base.Add(time.Duration(i)*time.Second).Unix(), i))
		require.NoError(t, os.WriteFile(name, []byte("{}\n"), 0o600))
		stamp := base.Add(time.Duration(i) * time.Second)
		require.NoError(t, os.Chtimes(name, stamp, stamp))
	}
	pruneVaneNativeFiles(dir)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, vaneNativeRetainedFiles, "rotated files are capped")
	_, err = os.Stat(filepath.Join(dir, "vane-native-v1.run.0.0.jsonl.ready"))
	require.True(t, os.IsNotExist(err), "the oldest files go first")
}

func TestVaneNativeReleaseDeadlineContinuesReload(t *testing.T) {
	previous := vaneNativeReleaseDeadline
	vaneNativeReleaseDeadline = 30 * time.Millisecond
	t.Cleanup(func() { vaneNativeReleaseDeadline = previous })
	collector := &vaneNativeCollector{
		registryKey: "deadline-test", references: 1,
		stop: make(chan struct{}), done: make(chan struct{}), started: make(chan error, 1),
	}
	vaneNativeCollectorRegistry.Lock()
	vaneNativeCollectorRegistry.entries["deadline-test"] = collector
	vaneNativeCollectorRegistry.Unlock()
	t.Cleanup(func() {
		vaneNativeCollectorRegistry.Lock()
		delete(vaneNativeCollectorRegistry.entries, "deadline-test")
		vaneNativeCollectorRegistry.Unlock()
	})

	start := time.Now()
	releaseVaneNativeCollector(collector)
	require.Less(t, time.Since(start), time.Second, "the reload must not wait forever for a stuck collector")
	require.True(t, collector.stopped, "the stop signal was still delivered")
}

// TEST-PICK-PROBE-EVIDENCE-01 (2026-11-28 production incident): a node that
// went bad keeps its 7-day learning score because all its flows left and no
// fresh samples arrive — the pick then steers new flows onto it (probe said
// 0.15Mbps, pick tp=0.42, twice in a row). A fresh non-cap-hit probe now caps
// the candidate's throughput estimate; a cap-hit record is a floor and never
// demotes.
func TestVanePickUsesFreshProbeEvidence(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	now := clock.Now()
	group.observeThroughputEpochIdentity(alpha.Name(), alpha.identity, 1, vaneTransportTCP, now, 20_000_000)
	group.observeThroughputEpochIdentity(alpha.Name(), alpha.identity, 1, vaneTransportTCP, now.Add(time.Second), 20_000_000)

	lease := func(name, identity string) vaneMemberLease { return vaneMemberLease{name: name, identity: identity} }
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease(alpha.Name(), alpha.identity)] = vaneCapabilityRecord{lowerBoundBPS: 150_000, bytes: 4096, observedAt: now}
	group.racingRuntime.capabilities[lease(beta.Name(), beta.identity)] = vaneCapabilityRecord{lowerBoundBPS: 17_800_000, bytes: 1000, observedAt: now}
	group.racingRuntime.mu.Unlock()

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, beta.Name(), decision.proxy.Name(),
		"alpha's 20M learning score must be capped by its fresh 0.15M probe")

	// Cap-hit records are floors: the same numbers with bytes at the cap must
	// not demote anyone, so alpha's learning estimate stands.
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease(alpha.Name(), alpha.identity)] = vaneCapabilityRecord{lowerBoundBPS: 150_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.capabilities[lease(beta.Name(), beta.identity)] = vaneCapabilityRecord{lowerBoundBPS: 17_800_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.mu.Unlock()
	decision = group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), decision.proxy.Name(),
		"a cap-hit probe proves a floor and must not cap the learning estimate")
}
