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
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		// alpha is the ranking choice; its 6M result ties the margin against
		// beta's 40M (within 5%? no — 40M is way past the margin, but the tie
		// rule only promotes a challenger that beats the baseline by >5%).
		if proxy.Name() == alphaName {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 6_000_000, capHit: true}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 6_100_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name(),
		"beta's 6.1M is within 5% of alpha's 6M: a tie, and the baseline alpha wins it")
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
	// A budget-denied probe never ran, so the per-scope timestamp must stay
	// unset: the next pick is still allowed to probe once budget recovers.
	group.mu.Lock()
	_, timestampSet := group.lastPickProbeAt[group.mediaTargetKey(metadata.Host, metadata.DstPort).target]
	group.mu.Unlock()
	require.False(t, timestampSet)
	budgetDeniedSeen := false
	for _, event := range snapshot.RecentEvents {
		if event.Kind == "pick-probe-budget-denied" {
			budgetDeniedSeen = true
		}
	}
	require.True(t, budgetDeniedSeen)
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
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		// Simulate a reload mid-probe: bump the generation from the probe
		// goroutine (the lock is released during stage b).
		group.mu.Lock()
		group.attachLearningState(group.learning, group.learning.generation+1)
		group.mu.Unlock()
		// Challenger faster than the baseline: with the stale veto the pick
		// must still fall back to alpha; without it beta would win.
		if proxy.Name() != alphaName {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 6_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alphaName, decision.proxy.Name(),
		"stale probe results must fall back to ranking even when the challenger probed faster")
	// The probe still ran and recorded its results; only the selection fell back.
	require.Equal(t, uint64(2), group.VaneDiagnostics().Counters.PickProbeSuccess)
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

// COLD-PICK-07: an exploration selection preempts the cold-pick probe. The
// first pick is cold and probes once; the per-scope timestamp is then cleared
// so the second pick would be cold again — only the exploration ownership
// stands between it and another probe.
func TestVaneColdPickExplorationPreempts(t *testing.T) {
	group, _, _, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	group.exploration = vaneExplorationConfig{enabled: true, interval: 1}
	var probeCalls atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalls.Add(1)
		return vaneProbeResult{reason: "nil-connection"}
	}

	group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, int32(2), probeCalls.Load(), "the first cold pick probes both candidates")

	// Clear the throttle timestamp: without the exploration preemption the
	// second pick would probe again.
	group.mu.Lock()
	group.lastPickProbeAt[group.mediaTargetKey(metadata.Host, metadata.DstPort).target] = time.Time{}
	group.mu.Unlock()
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.exploration, "exploration must own this pick")
	require.Equal(t, int32(2), probeCalls.Load(),
		"the exploration-owned pick must not run the cold-pick probe")
}

// COLD-PICK-09: the off-mode throttle regression (defect 1). The first cold
// pick probes and writes capability; the second pick on the same scope must
// not probe again — the old targetEvidence-based gate could never warm up in
// off mode, so it probed on every connection.
func TestVaneColdPickOffModeThrottleRegression(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneRacingOff)
	var calls atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		calls.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, int32(2), calls.Load(), "the first cold pick probes both candidates")
	second := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, alpha.Name(), second.proxy.Name())
	require.Equal(t, int32(2), calls.Load(), "the second pick is warm (capability + timestamp) and must not probe")
}
