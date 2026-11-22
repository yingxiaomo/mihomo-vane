package outboundgroup

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func profileEstimate(value, evidence, confidence float64) vaneMetricEstimate {
	return vaneMetricEstimate{value: value, evidence: evidence, confidence: confidence, valid: true}
}

// SCORE-SUCCESS-01: a node with 90/100 successes must cost less than one with
// 1/10 — the sample-count confidence is the whole point of the dimension.
func TestVaneScoreSuccessRate(t *testing.T) {
	good := vaneMetricsSnapshot{success: profileEstimate(0.9, 100, 1)}
	bad := vaneMetricsSnapshot{success: profileEstimate(0.1, 10, 1)}
	require.Less(t, scoreVaneMetrics(vaneSceneDefault, good), scoreVaneMetrics(vaneSceneDefault, bad))
}

// SCORE-SUCCESS-02: one sample is not evidence; the node estimate keeps the
// confidence low and the cost near neutral.
func TestVaneScoreSuccessSingleSampleIsNeutral(t *testing.T) {
	now := time.Now()
	state := vaneNodeState{successCount: 1, countersAt: now}
	single := vaneMetricsSnapshot{success: state.successEstimate(now)}
	require.InDelta(t, 0.1, single.success.confidence, 1e-9)

	cost := func(snapshot vaneMetricsSnapshot) float64 {
		return vaneMetricCost(snapshot.success, vaneMetricSuccess, func(value float64) float64 {
			return 1 - vaneClamp(value, 0, 1)
		})
	}
	require.InDelta(t, cost(vaneMetricsSnapshot{}), cost(single), 0.06)
}

// SCORE-MAX-01: max download rate uses the throughput cost curve.
func TestVaneScoreMaxRate(t *testing.T) {
	fast := vaneMetricsSnapshot{maxRate: profileEstimate(math.Log(50_000_000), 1, 1)}
	slow := vaneMetricsSnapshot{maxRate: profileEstimate(math.Log(5_000_000), 1, 1)}
	require.Less(t, scoreVaneMetrics(vaneSceneDefault, fast), scoreVaneMetrics(vaneSceneDefault, slow))
}

// SCORE-MAX-02: profile dimensions only nudge — they cannot overturn a wide
// gap on the base dimensions.
func TestVaneScoreMaxRateDoesNotOverturnBaseGap(t *testing.T) {
	strong := vaneMetricsSnapshot{
		failure: profileEstimate(0, 10, 1), connect: profileEstimate(math.Log(20), 10, 1),
		response: profileEstimate(math.Log(30), 10, 1), throughput: profileEstimate(math.Log(40_000_000), 10, 1),
		jitter: profileEstimate(1, 10, 1), maxRate: profileEstimate(math.Log(1_000_000), 1, 1),
	}
	weak := vaneMetricsSnapshot{
		failure: profileEstimate(1, 10, 1), connect: profileEstimate(math.Log(1400), 10, 1),
		response: profileEstimate(math.Log(2900), 10, 1), throughput: profileEstimate(math.Log(4_000_000), 10, 1),
		jitter: profileEstimate(90, 10, 1), maxRate: profileEstimate(math.Log(200_000_000), 1, 1),
	}
	require.Less(t, scoreVaneMetrics(vaneSceneMedia, strong), scoreVaneMetrics(vaneSceneMedia, weak))
}

// SCORE-DURATION-01: long-lived sockets are the stability signal.
func TestVaneScoreDuration(t *testing.T) {
	long := vaneMetricsSnapshot{duration: profileEstimate(600, 10, 1)}
	short := vaneMetricsSnapshot{duration: profileEstimate(5, 10, 1)}
	require.Less(t, scoreVaneMetrics(vaneSceneDefault, long), scoreVaneMetrics(vaneSceneDefault, short))
}

// SCORE-TOTAL-01: a proven node gets a bonus, an unproven one stays neutral.
func TestVaneScoreDownloadTotal(t *testing.T) {
	proven := vaneMetricsSnapshot{downloadTotal: profileEstimate(math.Log10(500<<20), 1, 1)}
	unproven := vaneMetricsSnapshot{}
	require.Less(t, scoreVaneMetrics(vaneSceneBulk, proven), scoreVaneMetrics(vaneSceneBulk, unproven))
	// Neutral means exactly the missing cost, not "best".
	total := vaneMetricCost(vaneMetricsSnapshot{}.downloadTotal, vaneMetricDownloadTotal, vaneDownloadTotalCost)
	require.InDelta(t, 0.5, total, 1e-9)
}

// SCORE-WEIGHT-01: ten dimensions, normalized to 1.0.
func TestVaneScoreWeightsNormalize(t *testing.T) {
	for _, scene := range []vaneScene{vaneSceneDefault, vaneSceneInteractive, vaneSceneMedia, vaneSceneBulk} {
		scoring := vaneScoring(scene)
		require.InDelta(t, 1.0, vaneSceneScoringSum(scoring), 1e-9, "scene %v", scene)
		for _, weight := range []float64{scoring.failureWeight, scoring.connectWeight, scoring.responseWeight,
			scoring.throughputWeight, scoring.jitterWeight, scoring.lossWeight, scoring.successWeight,
			scoring.maxRateWeight, scoring.durationWeight, scoring.downloadTotalWeight} {
			require.Greater(t, weight, 0.0, "scene %v", scene)
		}
	}
}

// PERSIST-C-01: the profile counters survive a reload and feed the estimates.
func TestVanePersistProfileCounters(t *testing.T) {
	now := time.Now()
	node := vanePersistedNode{
		Name: "alpha", Identity: "id", LastSeen: now,
		SuccessCount: 9, FailureCount: 1, CountersAt: now,
		MaxDownloadRate: 50_000_000, MaxRateAt: now,
		TotalDuration: int64(6000 * time.Second / time.Millisecond), DurationCount: 10, TotalsAt: now,
		DownloadTotal: 500 << 20,
	}
	state, ok, invalid := restoreVaneNode(node, now)
	require.True(t, ok)
	require.False(t, invalid)
	snapshot := state.snapshot(vaneTransportTCP, now)
	require.InDelta(t, 0.9, snapshot.success.value, 1e-9)
	require.InDelta(t, math.Log(50_000_000), snapshot.maxRate.value, 1e-9)
	require.InDelta(t, 600, snapshot.duration.value, 1e-9)
	require.InDelta(t, math.Log10(500<<20), snapshot.downloadTotal.value, 1e-9)
}

// PERSIST-C-02: an old payload without the new fields restores without error
// and leaves the dimensions neutral.
func TestVanePersistProfileLegacyPayload(t *testing.T) {
	now := time.Now()
	node := vanePersistedNode{Name: "alpha", Identity: "id", LastSeen: now}
	state, ok, invalid := restoreVaneNode(node, now)
	require.False(t, ok, "no metrics and no counters is not a node")
	require.False(t, invalid)
	require.Nil(t, state)
}

// PERSIST-C-03: a group untouched for more than seven days is dropped.
func TestVanePersistProfileAgeReset(t *testing.T) {
	now := time.Now()
	stale := now.Add(-vaneProfileAgeReset - time.Hour)
	node := vanePersistedNode{
		Name: "alpha", Identity: "id", LastSeen: now,
		SuccessCount: 5, FailureCount: 0, CountersAt: stale,
		MaxDownloadRate: 50_000_000, MaxRateAt: now,
		TotalDuration: int64(100 * time.Second / time.Millisecond), DurationCount: 2, TotalsAt: stale,
		DownloadTotal: 10 << 20,
	}
	state, ok, _ := restoreVaneNode(node, now)
	require.True(t, ok, "the fresh max-rate group keeps the node alive")
	snapshot := state.snapshot(vaneTransportTCP, now)
	require.Zero(t, state.successCount, "the restore drops a stale counter group")
	require.Zero(t, state.durationCount)
	require.Zero(t, state.downloadTotal)
	require.False(t, snapshot.success.valid)
	require.False(t, snapshot.duration.valid)
	require.False(t, snapshot.downloadTotal.valid)
	require.True(t, snapshot.maxRate.valid)
}

// PERSIST-C-04: counters alone keep a node alive even when every metric is
// invalid, so durability is not wasted.
func TestVanePersistProfileCountersKeepNodeAlive(t *testing.T) {
	now := time.Now()
	node := vanePersistedNode{
		Name: "alpha", Identity: "id", LastSeen: now,
		SuccessCount: 3, CountersAt: now,
	}
	state, ok, _ := restoreVaneNode(node, now)
	require.True(t, ok)
	require.NotNil(t, state)
	require.True(t, state.snapshot(vaneTransportTCP, now).success.valid)
}

// PERSIST-C-05: out-of-domain values are invalid at restore (never clamped in
// place), and computed values stay inside [0,1].
func TestVanePersistProfileInvalidValues(t *testing.T) {
	now := time.Now()
	node := vanePersistedNode{
		Name: "alpha", Identity: "id", LastSeen: now,
		SuccessCount: 0, FailureCount: 0, CountersAt: now,
		MaxDownloadRate: math.NaN(), MaxRateAt: now,
		TotalDuration: -5, TotalsAt: now,
	}
	state, ok, invalid := restoreVaneNode(node, now)
	require.True(t, invalid)
	require.False(t, ok)
	require.Nil(t, state)

	clamped := vaneNodeState{successCount: 3, failureCount: 1, countersAt: now}
	estimate := clamped.successEstimate(now)
	require.Equal(t, 0.75, estimate.value)
	require.LessOrEqual(t, estimate.value, 1.0)

	overflow := vaneNodeState{successCount: 1, failureCount: 0, countersAt: now}
	require.GreaterOrEqual(t, overflow.successEstimate(now).value, 0.0)
}

// SCORE-MISSING-01: every new dimension must declare a neutral missing cost;
// a missing spec would silently score it as "best".
func TestVaneScoreProfileMissingCosts(t *testing.T) {
	for _, kind := range []vaneMetricKind{vaneMetricLoss, vaneMetricSuccess, vaneMetricMaxRate,
		vaneMetricDuration, vaneMetricDownloadTotal} {
		require.InDelta(t, 0.5, vaneSpec(kind).missingCost, 1e-9)
		require.InDelta(t, 0.5, vaneMetricCost(vaneMetricEstimate{}, kind, func(float64) float64 { return 0 }), 1e-9)
	}
}

// SCORE-MAX-03: the peak only rises and keeps the raw BPS.
func TestVaneNodeRecordMaxRate(t *testing.T) {
	now := time.Now()
	var state vaneNodeState
	state.recordMaxRate(now, 50_000_000)
	state.recordMaxRate(now, 10_000_000)
	require.Equal(t, 50_000_000.0, state.maxDownloadRate)
	state.recordMaxRate(now, math.Inf(1))
	require.Equal(t, 50_000_000.0, state.maxDownloadRate)
}

// PERSIST-C-06: the real persist builder carries the profile counters, not just
// a hand-built payload.
func TestVanePersistProfileRoundTrip(t *testing.T) {
	now := time.Now()
	state := &vaneNodeState{name: "alpha", identity: "alpha-00000001", lastObservedAt: now}
	state.successCount, state.failureCount, state.countersAt = 9, 1, now
	state.recordMaxRate(now, 50_000_000)
	state.totalDuration, state.durationCount, state.totalsAt = 600*time.Second, 10, now
	state.downloadTotal = 500 << 20

	learning := &vaneLearningState{nodes: map[string]*vaneNodeState{"alpha": state}}
	snapshot := learning.snapshotLocked(now)
	require.Len(t, snapshot.Nodes, 1)
	restored, ok, _ := restoreVaneNode(snapshot.Nodes[0], now)
	require.True(t, ok)
	require.Equal(t, uint64(9), restored.successCount)
	require.Equal(t, uint64(1), restored.failureCount)
	require.Equal(t, 50_000_000.0, restored.maxDownloadRate)
	require.Equal(t, 600*time.Second, restored.totalDuration)
	require.Equal(t, uint64(500<<20), restored.downloadTotal)
}

// SCORE-COST-01: the three new cost curves keep their anchor semantics.
func TestVaneProfileCostCurves(t *testing.T) {
	require.Zero(t, vaneLossCost(0))
	require.Zero(t, vaneLossCost(0.01))
	require.Equal(t, 1.0, vaneLossCost(0.05))
	require.Equal(t, 1.0, vaneLossCost(0.5))
	require.InDelta(t, 0.5, vaneLossCost(0.03), 1e-9)

	require.Equal(t, 1.0, vaneDurationCost(1, 10, 300))
	require.Zero(t, vaneDurationCost(600, 10, 300))
	require.InDelta(t, 0.5, vaneDurationCost(155, 10, 300), 1e-9)

	require.Equal(t, 1.0, vaneDownloadTotalCost(5))
	require.Zero(t, vaneDownloadTotalCost(9))
	require.InDelta(t, 0.5, vaneDownloadTotalCost(7), 1e-9)
}


