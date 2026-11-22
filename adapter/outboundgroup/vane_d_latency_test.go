package outboundgroup

import (
	"math"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// LATENCY-01: a real media window's RTT feeds the node's latency EMA.
func TestVaneLatencyIdentityFeedsEstimate(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	defer group.Close()
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")

	metadata := &C.Metadata{Host: "rr-lat.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, true, true)
	flow := newVaneMediaFlow(group, alpha.Name(), metadata)
	require.NotNil(t, flow)
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 20_000_000, TotalBytes: 8 << 20, Age: 20 * time.Second, Delivered: true,
		Latency: 40 * time.Millisecond, LatencySupported: true,
	})
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 20_000_000, TotalBytes: 8 << 20, Age: 20 * time.Second, Delivered: true,
		Latency: 60 * time.Millisecond, LatencySupported: true,
	})

	group.mu.Lock()
	state := group.nodes[alpha.Name()]
	estimate := state.latencyEstimate(clock.Now())
	samples := state.latencySamples
	group.mu.Unlock()

	require.Equal(t, uint64(2), samples)
	require.True(t, estimate.valid)
	// EMA alpha 0.2: 40 then 0.2*60+0.8*40 = 44ms.
	require.InDelta(t, math.Log(44), estimate.value, 1e-9)
	require.InDelta(t, 0.2, estimate.confidence, 1e-9)
}

// LATENCY-02: an unsupported RTT read is not a zero-latency sample.
func TestVaneLatencyUnsupportedNeverFeeds(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	defer group.Close()
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")

	metadata := &C.Metadata{Host: "rr-lat-nosupport.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, true, true)
	flow := newVaneMediaFlow(group, alpha.Name(), metadata)
	require.NotNil(t, flow)
	for i := 0; i < 3; i++ {
		flow.observe(vaneThroughputObservation{
			BitsPerSecond: 20_000_000, TotalBytes: 8 << 20, Age: 20 * time.Second, Delivered: true,
			Latency: 40 * time.Millisecond, LatencySupported: false,
		})
	}
	group.mu.Lock()
	samples := group.nodes[alpha.Name()].latencySamples
	estimate := group.nodes[alpha.Name()].latencyEstimate(clock.Now())
	group.mu.Unlock()
	require.Zero(t, samples)
	require.False(t, estimate.valid)
}

// LATENCY-03: no evidence is invalid, and invalid scores the neutral cost.
func TestVaneLatencyMissingIsNeutral(t *testing.T) {
	var state vaneNodeState
	require.False(t, state.latencyEstimate(time.Now()).valid)

	withLatency := vaneMetricsSnapshot{
		latency: vaneMetricEstimate{value: math.Log(40), confidence: 1, valid: true},
	}
	without := vaneMetricsSnapshot{}
	// A healthy 40ms node must score strictly lower cost than an unknown node.
	require.Less(t, scoreVaneMetrics(vaneSceneMedia, withLatency), scoreVaneMetrics(vaneSceneMedia, without))
}

// LATENCY-04: latency actually moves the score, in the log-ms cost curve.
func TestVaneLatencyEntersScoring(t *testing.T) {
	snapshot := func(ms float64) vaneMetricsSnapshot {
		return vaneMetricsSnapshot{
			latency: vaneMetricEstimate{value: math.Log(ms), confidence: 1, valid: true},
		}
	}
	fast, slow, awful := scoreVaneMetrics(vaneSceneMedia, snapshot(40)), scoreVaneMetrics(vaneSceneMedia, snapshot(300)), scoreVaneMetrics(vaneSceneMedia, snapshot(800))
	require.Less(t, fast, slow)
	require.Less(t, slow, awful)
	// Weight is 0.20; a 40ms -> 800ms swing must move the cost by the full step.
	require.InDelta(t, 200_000, float64(awful-fast), 5_000)
}

// LATENCY-05: a stale reading is dropped instead of being trusted forever.
func TestVaneLatencyStaleIsInvalid(t *testing.T) {
	now := time.Now()
	state := vaneNodeState{
		latencyMs: 40, latencySamples: 3, latencyAt: now.Add(-vaneProfileAgeReset - time.Minute),
	}
	require.False(t, state.latencyEstimate(now).valid)

	state.latencyAt = now
	require.True(t, state.latencyEstimate(now).valid)
}

// LATENCY-06: the estimate crosses a reload, and an expired one is not restored.
func TestVaneLatencyPersistence(t *testing.T) {
	now := time.Now()
	fresh := vanePersistedNode{Name: "beta", Identity: "test:beta", LastSeen: now,
		LatencyMs: 55, LatencySamples: 4, LatencyAt: now}
	state, valid, invalid := restoreVaneNode(fresh, now)
	require.True(t, valid)
	require.False(t, invalid)
	require.InDelta(t, math.Log(55), state.latencyEstimate(now).value, 1e-9)
	require.True(t, state.latencyEstimate(now).valid, "a latency-only profile still counts as evidence")

	stale := fresh
	stale.LatencyAt = now.Add(-vaneProfileAgeReset - time.Minute)
	state, valid, _ = restoreVaneNode(stale, now)
	require.False(t, valid, "stale latency alone must not keep a node alive")
	if state != nil {
		require.False(t, state.latencyEstimate(now).valid)
	}
}

// CUMUL-DECAY-01: a cumulative-loss pair older than the profile age no longer
// counts, so a node is not labelled lossy forever.
func TestVaneCumulativeLossDecays(t *testing.T) {
	now := time.Now()
	state := vaneNodeState{cumulSent: 10_000, cumulRetrans: 900, cumulAt: now}
	rate, ok := state.cumulLossRate(now)
	require.True(t, ok)
	require.InDelta(t, 0.09, rate, 1e-9)

	state.cumulAt = now.Add(-vaneProfileAgeReset - time.Minute)
	_, ok = state.cumulLossRate(now)
	require.False(t, ok, "a 7 day old loss ratio must not gate knownGood")
	require.False(t, state.lossEstimate(now).valid)
}

// CUMUL-DECAY-02: a zero timestamp also decays (nodes written by older builds
// carry no cumulAt).
func TestVaneCumulativeLossZeroTimestampDecays(t *testing.T) {
	now := time.Now()
	state := vaneNodeState{cumulSent: 10_000, cumulRetrans: 900}
	_, ok := state.cumulLossRate(now)
	require.False(t, ok)
}

// CUMUL-DECAY-03: the counters are still restored while fresh, dropped when stale.
func TestVaneCumulativeLossRestoreRespectsAge(t *testing.T) {
	now := time.Now()
	// The record must be alive on its own (counters are profile evidence), or
	// restore drops the whole node before the cumulative pair is considered.
	fresh := vanePersistedNode{Name: "beta", Identity: "test:beta", LastSeen: now,
		SuccessCount: 2, CountersAt: now,
		CumulSent: 10_000, CumulRetrans: 900, CumulObservedAt: now}
	state, _, _ := restoreVaneNode(fresh, now)
	require.Equal(t, uint64(10_000), state.cumulSent)
	rate, ok := state.cumulLossRate(now)
	require.True(t, ok)
	require.InDelta(t, 0.09, rate, 1e-9)

	stale := fresh
	stale.CumulObservedAt = now.Add(-vaneProfileAgeReset - time.Minute)
	state, _, _ = restoreVaneNode(stale, now)
	require.NotNil(t, state, "the identity still exists, only the counters expire")
	require.Zero(t, state.cumulSent)
	require.Zero(t, state.cumulRetrans)
	_, ok = state.cumulLossRate(now)
	require.False(t, ok)
}

// CUMUL-DECAY-04: booking new counters refreshes the timestamp, so an active
// node's old loss history keeps decaying instead of expiring in one step.
func TestVaneCumulativeLossTimestampRefreshes(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	defer group.Close()

	metadata := &C.Metadata{Host: "rr-cumul.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, true, true)
	group.mu.Lock()
	identity, epoch := group.nodes[alpha.Name()].identity, group.nodes[alpha.Name()].epoch
	group.mu.Unlock()

	start := clock.Now()
	group.recordCumulativeLossIdentity(alpha.Name(), identity, epoch, vaneConnectionCloseObservation{
		SegsOut: 100, RetransSegs: 2, LossSupported: true,
	})

	group.mu.Lock()
	state := group.nodes[alpha.Name()]
	at, sent := state.cumulAt, state.cumulSent
	group.mu.Unlock()
	require.Equal(t, uint64(100), sent)
	require.False(t, at.IsZero())
	require.False(t, at.Before(start), "the observation must stamp the counters")

	clock.Advance(vaneProfileAgeReset + time.Minute)
	group.mu.Lock()
	_, ok := group.nodes[alpha.Name()].cumulLossRate(clock.Now())
	group.mu.Unlock()
	require.False(t, ok, "untouched counters age out")
}
