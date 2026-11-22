package outboundgroup

// Acceptance tests for the off-mode evidence probe (P0 deadlock breaker), the
// recently-fast grace (P1 background mis-close mitigation) and the stall
// watchdog (§2.4): OFF-NO-EVIDENCE-PROBE-01..04, FAST-GRACE-01..03,
// WATCHDOG-01..03.

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

type offProbeRig struct {
	group    *Vane
	clock    *vaneConnTestClock
	alpha    *vaneTestProxy
	beta     *vaneTestProxy
	flow     *vaneMediaFlow
	metadata *C.Metadata
}

// newOffProbeRig builds an off-mode media group (alpha current, beta the only
// challenger) with the sample age/size gates relaxed so a single low sample
// can reach the trigger.
func newOffProbeRig(t *testing.T) *offProbeRig {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	// The raw helper bypasses NewVane, so the racing config (budget, URL,
	// probe) must be applied explicitly — off mode here.
	configureVaneRacingForTest(t, group, vaneRacingOff)
	group.media.lowThroughputBPS = 5_000_000
	group.media.lowWindows = 3
	group.media.maxLowWindows = 4
	group.media.minAge = 0
	group.media.minBytes = 0
	group.media.bufferGuard = 0
	group.media.demandBPS = 1_000_000
	metadata := &C.Metadata{Host: "rr-off.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	return &offProbeRig{group: group, clock: clock, alpha: alpha, beta: beta, flow: flow, metadata: metadata}
}

func (r *offProbeRig) lowSample() vaneThroughputObservation {
	return vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
}

func countVaneEvents(group *Vane, kind string, reason string) int {
	count := 0
	for _, event := range group.VaneDiagnostics().RecentEvents {
		if event.Kind == kind && (reason == "" || event.Reason == reason) {
			count++
		}
	}
	return count
}

func (r *offProbeRig) capabilityWritten(name string) bool {
	r.group.racingRuntime.mu.Lock()
	defer r.group.racingRuntime.mu.Unlock()
	for member := range r.group.racingRuntime.capabilities {
		if member.name == name {
			return true
		}
	}
	return false
}

// OFF-NO-EVIDENCE-PROBE-01: with every candidate evidence-less, the third low
// window is suppressed but schedules the evidence probe; the probe writes the
// capability cache (top-ranked candidate only) and the next low window can
// then close through the normal baseline path.
func TestVaneOffModeEvidenceProbeBreaksDeadlock(t *testing.T) {
	rig := newOffProbeRig(t)
	var probeCalls, probedBeta atomic.Int32
	rig.group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		probeCalls.Add(1)
		if proxy.Name() == rig.beta.Name() {
			probedBeta.Add(1)
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}

	low := rig.lowSample()
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low), "the third low window is suppressed by the evidence gate")
	require.Eventually(t, func() bool { return rig.capabilityWritten(rig.beta.Name()) }, 2*time.Second, time.Millisecond,
		"the evidence probe must fill the capability cache")
	require.Equal(t, int32(1), probeCalls.Load(), "only the top-ranked candidate is probed")
	require.Equal(t, int32(1), probedBeta.Load())
	require.Equal(t, 1, countVaneEvents(rig.group, "reconnect-suppressed", "no-evidence-candidate"))
	require.Equal(t, 1, countVaneEvents(rig.group, "evidence-probe-scheduled", ""))
	require.Equal(t, 1, countVaneEvents(rig.group, "evidence-probe-success", ""))

	// The next low window sees the fresh capability and baseline closes.
	action := rig.flow.observe(low)
	require.NotNil(t, action, "with evidence the baseline can close")
	require.True(t, action(), "the baseline commit must be executable")
}

// OFF-NO-EVIDENCE-PROBE-02: a budget-denied probe records a diagnostic, does
// not probe, and leaves the throttle open so the next low window can retry
// once budget recovers.
func TestVaneOffModeEvidenceProbeBudgetDenied(t *testing.T) {
	rig := newOffProbeRig(t)
	var probeCalls atomic.Int32
	rig.group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalls.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}
	rig.group.racingRuntime.mu.Lock()
	rig.group.racingRuntime.budget = vaneRacingBudget{startedAt: rig.clock.Now(), used: rig.group.racing.budgetBytesHour}
	rig.group.racingRuntime.mu.Unlock()

	low := rig.lowSample()
	for i := 0; i < 3; i++ {
		require.Nil(t, rig.flow.observe(low))
	}
	require.Eventually(t, func() bool { return countVaneEvents(rig.group, "evidence-probe-budget-denied", "") == 1 }, time.Second, time.Millisecond)
	require.Zero(t, probeCalls.Load(), "a denied probe never runs")

	// Budget recovers: the next low window retries (the denial left no stamp).
	rig.group.racingRuntime.mu.Lock()
	rig.group.racingRuntime.budget = vaneRacingBudget{startedAt: rig.clock.Now()}
	rig.group.racingRuntime.mu.Unlock()
	require.Nil(t, rig.flow.observe(low))
	require.Eventually(t, func() bool { return probeCalls.Load() == 1 }, 2*time.Second, time.Millisecond,
		"the retry after budget recovery must probe")
}

// OFF-NO-EVIDENCE-PROBE-03: one probe per flow/round in flight and one per
// target per throttle window.
func TestVaneOffModeEvidenceProbeThrottled(t *testing.T) {
	rig := newOffProbeRig(t)
	var probeCalls atomic.Int32
	rig.group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalls.Add(1)
		// Below the close bar on purpose: prepare keeps failing, so every low
		// window tries to schedule and only the throttle dedupes.
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 1_000_000, capHit: true}
	}

	low := rig.lowSample()
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	require.Eventually(t, func() bool { return probeCalls.Load() == 1 }, 2*time.Second, time.Millisecond)
	// Back-to-back low windows in the same round (and any round within the
	// throttle) must not probe again.
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, int32(1), probeCalls.Load(), "the throttle/dedupe must suppress repeats")

	rig.clock.Advance(vaneMediaEvidenceProbeThrottle - time.Second)
	require.Nil(t, rig.flow.observe(low))
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, int32(1), probeCalls.Load(), "still inside the throttle window")

	rig.clock.Advance(2 * time.Second)
	require.Nil(t, rig.flow.observe(low))
	require.Eventually(t, func() bool { return probeCalls.Load() == 2 }, 2*time.Second, time.Millisecond,
		"after the throttle expires the probe may run again")
}

// OFF-NO-EVIDENCE-PROBE-04: a recovery while the probe is in flight changes
// nothing about flow state — the result only lands in the capability cache.
func TestVaneOffModeEvidenceProbeSurvivesRecovery(t *testing.T) {
	rig := newOffProbeRig(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	rig.group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		select {
		case <-release:
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
		case <-ctx.Done():
			return vaneProbeResult{reason: "canceled"}
		}
	}

	low := rig.lowSample()
	for i := 0; i < 3; i++ {
		require.Nil(t, rig.flow.observe(low))
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("evidence probe did not start")
	}
	// The flow recovers while the probe is in flight.
	require.Nil(t, rig.flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 9 * 1024 * 1024, Age: 21 * time.Second}))
	close(release)

	// The callback writes only the capability cache: no close, no commit.
	require.Eventually(t, func() bool { return rig.capabilityWritten(rig.beta.Name()) }, 2*time.Second, time.Millisecond)
	snapshot := rig.group.VaneDiagnostics()
	require.Zero(t, snapshot.Counters.ReconnectCommitted)
	require.Zero(t, snapshot.Counters.ReconnectPrepared)
	rig.flow.mu.Lock()
	closed := rig.flow.closed
	aborted := rig.flow.aborted
	rig.flow.mu.Unlock()
	require.False(t, closed)
	require.False(t, aborted)
}

// FAST-GRACE-01: low windows within the grace of a fast sample never count.
func TestVaneFastGraceDefersStreak(t *testing.T) {
	rig := newOffProbeRig(t)
	require.Nil(t, rig.flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 4 * 1024 * 1024, Age: 10 * time.Second}))
	low := rig.lowSample()
	for i := 0; i < 3; i++ {
		rig.clock.Advance(5 * time.Second)
		require.Nil(t, rig.flow.observe(low), "graced lows must not trigger a close")
	}
	rig.flow.mu.Lock()
	count := rig.flow.lowWindows
	rig.flow.mu.Unlock()
	require.Zero(t, count, "graced lows must not accumulate")
	require.Zero(t, countVaneEvents(rig.group, "reconnect-suppressed", ""))
	require.Equal(t, 3, countVaneEvents(rig.group, "low-window-graced", "recently-fast"))
}

// FAST-GRACE-02: once the grace expires a genuine collapse still closes.
func TestVaneFastGraceExpiresAndCloses(t *testing.T) {
	rig := newOffProbeRig(t)
	seedChain01Capability(t, rig.group, vaneMemberLease{name: rig.beta.Name(), identity: rig.beta.identity, epoch: 0}, 40_000_000, rig.clock.Now())
	require.Nil(t, rig.flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 4 * 1024 * 1024, Age: 10 * time.Second}))
	low := rig.lowSample()
	// Inside the grace the streak does not count.
	rig.clock.Advance(5 * time.Second)
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	// Past the grace the streak accumulates and the third low window closes.
	rig.clock.Advance(vaneMediaFastGrace)
	var action vanePolicyAction
	for i := 0; i < 3 && action == nil; i++ {
		rig.clock.Advance(5 * time.Second)
		action = rig.flow.observe(low)
	}
	require.NotNil(t, action, "a collapse beyond the grace must still close")
}

// FAST-GRACE-03: a flow that was never fast gets no grace (no regression).
func TestVaneFastGraceInactiveWithoutFastSample(t *testing.T) {
	rig := newOffProbeRig(t)
	seedChain01Capability(t, rig.group, vaneMemberLease{name: rig.beta.Name(), identity: rig.beta.identity, epoch: 0}, 40_000_000, rig.clock.Now())
	low := rig.lowSample()
	var action vanePolicyAction
	for i := 0; i < 3; i++ {
		action = rig.flow.observe(low)
	}
	require.NotNil(t, action, "three lows without any fast sample trigger as before")
	require.Zero(t, countVaneEvents(rig.group, "low-window-graced", ""))
}

// WATCHDOG-01: a flow that sampled and then went fully silent gets synthetic
// windows, and the normal chain (evidence probe) runs.
func TestVaneStallWatchdogSynthesizesWindows(t *testing.T) {
	rig := newOffProbeRig(t)
	rig.group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}
	low := rig.lowSample()
	require.Nil(t, rig.flow.observe(low))
	require.Nil(t, rig.flow.observe(low))
	rig.clock.Advance(vaneMediaStallSilence)
	rig.group.runMediaWatchdogTick(rig.clock.Now())
	// throughput-sample events are counted, not appended to the ring, so the
	// synthetic window is asserted through its effect: the streak advances.
	rig.flow.mu.Lock()
	count := rig.flow.lowWindows
	rig.flow.mu.Unlock()
	require.Equal(t, 3, count, "silence accumulates toward the trigger")
	require.Equal(t, 1, countVaneEvents(rig.group, "evidence-probe-scheduled", ""),
		"the trigger fires and the off-mode evidence probe runs")
}

// WATCHDOG-02: never-sampled flows and closed flows get no synthetic windows.
func TestVaneStallWatchdogSkipsInactiveFlows(t *testing.T) {
	rig := newOffProbeRig(t)
	// Never sampled: just connected, not stalled.
	rig.clock.Advance(vaneMediaStallSilence * 3)
	rig.group.runMediaWatchdogTick(rig.clock.Now())
	rig.flow.mu.Lock()
	count := rig.flow.lowWindows
	rig.flow.mu.Unlock()
	require.Zero(t, count, "a flow that never sampled is not stalled")

	// Closed flow: sampled once, then closed; silence must not synthesize.
	require.Nil(t, rig.flow.observe(rig.lowSample()))
	rig.flow.markClosed()
	rig.clock.Advance(vaneMediaStallSilence * 3)
	rig.group.runMediaWatchdogTick(rig.clock.Now())
	rig.flow.mu.Lock()
	count = rig.flow.lowWindows
	closed := rig.flow.closed
	rig.flow.mu.Unlock()
	require.True(t, closed)
	require.Equal(t, 1, count, "a closed flow must not accumulate synthetic windows")
}

// WATCHDOG-03: synthetic windows obey the grace — a recently-fast flow that
// went silent is not treated as stalled.
func TestVaneStallWatchdogRespectsGrace(t *testing.T) {
	rig := newOffProbeRig(t)
	require.Nil(t, rig.flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 4 * 1024 * 1024, Age: 10 * time.Second}))
	rig.clock.Advance(vaneMediaStallSilence)
	rig.group.runMediaWatchdogTick(rig.clock.Now())
	rig.flow.mu.Lock()
	count := rig.flow.lowWindows
	rig.flow.mu.Unlock()
	require.Zero(t, count, "the synthetic window is graced, not counted")
	require.Equal(t, 1, countVaneEvents(rig.group, "low-window-graced", "recently-fast"))
}
