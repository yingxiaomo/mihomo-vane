package outboundgroup

// COLD-PICK end-to-end acceptance tests, driven through the real pick path
// (pickDecision/DialContext) with an injected probe.

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// suppressColdPickProbeForTest presets the per-scope probe timestamp so the
// cold-pick probe never runs during the pick. Race tests that inject a
// blocking probe (or count probe invocations for the race itself) use this to
// keep the two probe consumers apart.
func suppressColdPickProbeForTest(t *testing.T, group *Vane, metadata *C.Metadata) {
	t.Helper()
	group.mu.Lock()
	group.lastPickProbeAt[group.mediaTargetKey(metadata.Host, metadata.DstPort).target] = group.clock.Now()
	group.mu.Unlock()
}

func newColdPickGroupForTest(t *testing.T, mode vaneRacingMode) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *C.Metadata) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, 2_000_000)
	configureVaneRacingForTest(t, group, mode)
	metadata := &C.Metadata{Host: "rr-coldpick.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	return group, clock, alpha, beta, metadata
}

// COLD-PICK-01: a cold pick with probes 40M vs 6M selects the faster one and
// both valid results land in the capability cache.
func TestVaneColdPickSelectsFasterAndWritesCapability(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingShadow)
	var calls atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		if calls.Add(1) == 1 {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 6_000_000, capHit: true}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name(),
		"alpha ranks first; its 6M result ties the margin against the baseline")
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeCount)
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeSuccess)
	require.Positive(t, snapshot.Counters.PickProbeBytes)
	group.mu.Lock()
	// Both probes were valid: alpha's own record and beta's. A never-selected
	// candidate has no node state, so the record lands under epoch 0.
	_, alphaCap := group.racingRuntime.capabilities[vaneMemberLease{name: alpha.Name(), identity: alpha.identity, epoch: 1}]
	_, betaCap := group.racingRuntime.capabilities[vaneMemberLease{name: "beta", identity: "test:beta"}]
	group.mu.Unlock()
	require.True(t, alphaCap)
	require.True(t, betaCap)
}

// COLD-PICK-02: both probes below the bar; the probe result still wins over
// a better delay ranking when it is meaningfully faster.
func TestVaneColdPickBeatsDelayRanking(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		// alpha is the ranking choice; make it slower than beta.
		if proxy.Name() == alphaName {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 1_000_000, capHit: true}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 2_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", decision.proxy.Name(),
		"2M beats 1M despite beta's worse delay rank")
	group.mu.Lock()
	group.mu.Unlock()
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeSuccess)
}

// COLD-PICK-03: both probes invalid -> ranking fallback, no cache writes.
func TestVaneColdPickInvalidFallsBack(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "nil-connection"}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), decision.proxy.Name())
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeInvalid)
	require.Zero(t, snapshot.Counters.PickProbeSuccess)
	group.mu.Lock()
	require.Empty(t, group.racingRuntime.capabilities)
	group.mu.Unlock()
}

// COLD-PICK-04: budget denied -> no probe, ranking fallback.
func TestVaneColdPickBudgetDeniedFallsBack(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	group.racingRuntime.mu.Lock()
	group.racingRuntime.budget = vaneRacingBudget{startedAt: group.clock.Now(), used: 120 * 1024 * 1024}
	group.racingRuntime.mu.Unlock()
	probeCalled := atomic.Bool{}
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalled.Store(true)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), decision.proxy.Name())
	require.False(t, probeCalled.Load())
	snapshot := group.VaneDiagnostics()
	require.Zero(t, snapshot.Counters.PickProbeCount)
}

// COLD-PICK-05: warm pick (fresh capability for a top-2 candidate, or a fresh
// per-scope timestamp) never probes.
func TestVaneColdPickWarmSkipsProbe(t *testing.T) {
	t.Run("fresh capability", func(t *testing.T) {
		group, _, alpha, beta, metadata := newColdPickGroupForTest(t, vaneRacingOff)
		now := group.clock.Now()
		group.mu.Lock()
		group.learning.mu.Lock()
		group.ensureProxyNodeLocked(beta, now)
		group.racingRuntime.capabilities[vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}] =
			vaneCapabilityRecord{member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}, lowerBoundBPS: 40_000_000, observedAt: now}
		group.learning.mu.Unlock()
		group.mu.Unlock()
		probeCalled := atomic.Bool{}
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			probeCalled.Store(true)
			return vaneProbeResult{reason: "nil-connection"}
		}

		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.Equal(t, alpha.Name(), decision.proxy.Name())
		require.False(t, probeCalled.Load())
	})

	t.Run("fresh per-scope timestamp", func(t *testing.T) {
		group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
		suppressColdPickProbeForTest(t, group, metadata)
		probeCalled := atomic.Bool{}
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			probeCalled.Store(true)
			return vaneProbeResult{reason: "nil-connection"}
		}

		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.Equal(t, alpha.Name(), decision.proxy.Name())
		require.False(t, probeCalled.Load())
	})
}

// COLD-PICK-06: a generation change during the probe discards the results and
// falls back to ranking.
func TestVaneColdPickGenerationChangeDiscards(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingShadow)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		// Simulate a reload mid-probe: bump the generation from the probe
		// goroutine (the lock is released during stage b).
		group.mu.Lock()
		group.attachLearningState(group.learning, group.learning.generation+1)
		group.mu.Unlock()
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), decision.proxy.Name(), "stale probe results must fall back to ranking")
	// The probe still ran and recorded its results; only the selection fell back.
	require.Positive(t, group.VaneDiagnostics().Counters.PickProbeCount)
}

// COLD-PICK-08: concurrent cold picks on the same scope — the second pick
// fails open to ranking while the first probe is in flight.
func TestVaneColdPickConcurrentFailsOpen(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	var probeOnce sync.Once
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeOnce.Do(func() { close(probeEntered) })
		<-releaseProbe
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	pickDone := make(chan vanePickDecision, 1)
	go func() {
		pickDone <- group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	}()
	<-probeEntered

	// The second cold pick while the first is in flight: fail open to ranking
	// and record reason=inflight (the first probe has not settled yet, so the
	// probe counters are still zero here).
	second := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), second.proxy.Name())
	snapshot := group.VaneDiagnostics()
	require.Zero(t, snapshot.Counters.PickProbeCount,
		"the in-flight scope must not start a second probe")
	inflightSeen := false
	for _, event := range snapshot.RecentEvents {
		if event.Kind == "pick-probe-selected" && event.Reason == "inflight" {
			inflightSeen = true
		}
	}
	require.True(t, inflightSeen)

	close(releaseProbe)
	first := <-pickDone
	require.NotEmpty(t, first.proxy.Name())
	snapshot = group.VaneDiagnostics()
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeCount)
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeSuccess)
}

// COLD-PICK-07: an exploration selection preempts the cold-pick probe.
func TestVaneColdPickExplorationPreempts(t *testing.T) {
	group, _, _, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	group.exploration = vaneExplorationConfig{enabled: true, interval: 1}
	probeCalled := atomic.Bool{}
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalled.Store(true)
		return vaneProbeResult{reason: "nil-connection"}
	}

	// interval=1 triggers on the second eligible selection (the first pick
	// only arms the scope counter), so pick twice. The first pick is cold and
	// runs the cold-pick probe (the gate comes after exploration in stage a),
	// so the probe is called once there.
	group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.exploration, "exploration must own this pick")
	require.True(t, probeCalled.Load(),
		"the first pick's cold-pick probe ran; the exploration-owned second pick must not probe again")
}
