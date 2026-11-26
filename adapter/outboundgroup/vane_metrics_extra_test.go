package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func vaneFlowLowWindows(flow *vaneFlow) int {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	return flow.lowWindows
}

// METRIC-LOW-OR-01 / METRIC-LOSS-0x / METRIC-LATENCY-0x: the low-window line is
// the union of throughput, loss and latency. Loss and latency only count when
// the kernel reported them; a silent socket's stale srtt never counts.
func TestVaneFlowLowWindowSignalUnion(t *testing.T) {
	healthy := vaneThroughputObservation{
		BitsPerSecond: 10_000_000,
		TotalBytes:    8 * 1024 * 1024,
		Age:           20 * time.Second,
		Delivered:     true,
	}
	cases := []struct {
		name   string
		mutate func(*vaneThroughputObservation)
		want   int
	}{
		{"throughput", func(o *vaneThroughputObservation) { o.BitsPerSecond = 1_000_000 }, 1},
		{"loss", func(o *vaneThroughputObservation) { o.LossSupported, o.LossRate = true, 0.08 }, 1},
		{"loss-below-line", func(o *vaneThroughputObservation) { o.LossSupported, o.LossRate = true, 0.02 }, 0},
		{"loss-unsupported", func(o *vaneThroughputObservation) { o.LossRate = 0.08 }, 0},
		{"latency", func(o *vaneThroughputObservation) {
			o.LatencySupported, o.Latency = true, 800*time.Millisecond
		}, 1},
		{"latency-below-line", func(o *vaneThroughputObservation) {
			o.LatencySupported, o.Latency = true, 200*time.Millisecond
		}, 0},
		{"latency-unsupported", func(o *vaneThroughputObservation) { o.Latency = 800 * time.Millisecond }, 0},
		{"latency-stale-socket", func(o *vaneThroughputObservation) {
			o.LatencySupported, o.Latency, o.Delivered = true, 800*time.Millisecond, false
		}, 0},
		{"all-healthy", func(o *vaneThroughputObservation) {
			o.LossSupported, o.LatencySupported, o.Latency = true, true, 100*time.Millisecond
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, flow := newVaneObservationRig(t, vaneRacingOn)
			sample := healthy
			tc.mutate(&sample)
			require.Nil(t, flow.observe(sample))
			require.Equal(t, tc.want, vaneFlowLowWindows(flow))
		})
	}
}

// METRIC-LATENCY-RACE: a latency-only degradation must reach the normal
// streak → prepare/race chain, not just bump a counter.
func TestVaneLatencyOnlyStreakReachesRace(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneRacingOn)
	slowRTT := vaneThroughputObservation{
		BitsPerSecond:    10_000_000,
		TotalBytes:       8 * 1024 * 1024,
		Age:              20 * time.Second,
		Delivered:        true,
		LatencySupported: true,
		Latency:          800 * time.Millisecond,
	}
	for i := 0; i < vaneDefaultLowWindows; i++ {
		clock.Advance(5 * time.Second)
		require.Nil(t, flow.observe(slowRTT))
	}
	require.Equal(t, vaneDefaultLowWindows, vaneFlowLowWindows(flow))
	require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
}

func TestVaneTCPStatsRTT(t *testing.T) {
	var unsupported *vaneTCPStats
	_, ok := unsupported.rtt()
	require.False(t, ok, "nil stats never claim a latency")

	_, ok = (&vaneTCPStats{}).rtt()
	require.False(t, ok, "zero srtt means no timed sample")

	latency, ok := (&vaneTCPStats{rttMicros: 800_000}).rtt()
	require.True(t, ok)
	require.Equal(t, 800*time.Millisecond, latency)
}

// SETTLE-SIGNAL-01..05: the post-handoff verdict uses the same signal set as
// the low-window line, gated by a first-window size/delivery floor.
func TestVaneSettleUsesWindowSignals(t *testing.T) {
	base := vaneThroughputObservation{
		BitsPerSecond: 40_000_000,
		TotalBytes:    8 * 1024 * 1024,
		Age:           20 * time.Second,
		Delivered:     true,
	}
	withLatency := base
	withLatency.LatencySupported, withLatency.Latency = true, 800*time.Millisecond
	withLoss := base
	withLoss.LossSupported, withLoss.LossRate = true, 0.08
	unsupportedLatency := base
	unsupportedLatency.Latency = 800 * time.Millisecond
	smallNoisy := base
	smallNoisy.TotalBytes = 512 * 1024
	smallNoisy.LossSupported, smallNoisy.LossRate = true, 0.067

	cases := []struct {
		name     string
		sample   vaneThroughputObservation
		improved bool
	}{
		{"healthy", base, true},
		{"latency", withLatency, false},
		{"loss", withLoss, false},
		{"latency-unsupported", unsupportedLatency, true},
		{"first-window-small", smallNoisy, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group, _, _, beta, metadata := newTargetGroupForTest(t)
			chain01ProductionValues(t, group, 2_000_000)
			key := techdebtSettleTargetHandoff(t, group, metadata, beta, tc.sample)
			group.mu.Lock()
			_, preferred := group.targetPreferences[key]
			cooled := group.nodeCoolingLocked(beta.Name(), group.clock.Now())
			group.mu.Unlock()
			require.Equal(t, tc.improved, preferred, "preference follows the verdict")
			require.Equal(t, !tc.improved, cooled, "no-gain slow-cools the candidate for 30 minutes")
		})
	}
}

// EVIDENCE-DEGRADED-01/02: a fast window with bad loss or latency records
// target evidence that readers must not treat as admitting.
func TestVaneDegradedTargetEvidenceIsNotAdmitting(t *testing.T) {
	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	t.Run("flag round-trips", func(t *testing.T) {
		group, clock, _, beta, _ := newVaneRacingEvidenceGroup(t)
		key := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}).targetKey
		group.mu.Lock()
		lease := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.mu.Unlock()
		group.recordTargetEvidence(key, lease, 50_000_000, true)
		group.mu.Lock()
		bps, fresh, degraded := group.targetEvidenceLocked(key, lease, clock.Now())
		group.mu.Unlock()
		require.True(t, fresh)
		require.True(t, degraded)
		require.Equal(t, 50_000_000.0, bps)
	})

	t.Run("fast but degraded candidate is not probed", func(t *testing.T) {
		group, _, _, beta, _ := newVaneRacingEvidenceGroup(t)
		request := newVaneRaceRequestForTest(t, group, metadata)
		group.mu.Lock()
		betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.mu.Unlock()
		group.recordTargetEvidence(request.targetKey, betaLease, 50_000_000, true)

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1, "degraded evidence must not admit a challenger")
		require.Equal(t, "gamma", candidates[0].member.name)
	})
}
