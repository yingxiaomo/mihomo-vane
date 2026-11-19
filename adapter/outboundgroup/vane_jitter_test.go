package outboundgroup

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVaneJitterTracker(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	t.Run("JITTER-01 online mean squared deviation and ratio", func(t *testing.T) {
		var tracker vaneJitterTracker
		tracker.observeLatency(now, 10)
		require.False(t, tracker.estimate(now).valid, "one sample cannot define jitter")
		require.Zero(t, tracker.deviation.estimate(vaneMetricJitter, now).value, "the first sample uses itself as its initial mean")
		tracker.observeLatency(now, 20)
		tracker.observeLatency(now, 30)
		mean := tracker.mean.estimate(vaneMetricJitter, now).value
		variance := tracker.deviation.estimate(vaneMetricJitter, now).value
		require.InDelta(t, 20, mean, 1e-12)
		require.InDelta(t, (0+100+225)/3.0, variance, 1e-12, "deviation uses the preceding mean")
		estimate := tracker.estimate(now)
		require.True(t, estimate.valid)
		require.InDelta(t, math.Sqrt(variance), estimate.value, 1e-12)
		require.InDelta(t, estimate.value/mean, tracker.ratio(now), 1e-12)
	})

	t.Run("JITTER-02 one sample has no estimate", func(t *testing.T) {
		var tracker vaneJitterTracker
		tracker.observeLatency(now, 20)
		require.False(t, tracker.estimate(now).valid)
		require.Zero(t, tracker.ratio(now))
	})

	t.Run("JITTER-03 only connect observations contribute", func(t *testing.T) {
		var connectOnly, responseOnly vaneMetrics
		for i := 0; i < 2; i++ {
			connectOnly.observeConnect(now, 20*time.Millisecond)
			responseOnly.observeResponse(now, 120*time.Millisecond)
		}
		require.True(t, connectOnly.snapshot(now).jitter.valid)
		require.Zero(t, responseOnly.jitter.samples)
		require.False(t, responseOnly.snapshot(now).jitter.valid)
	})

	t.Run("JITTER-13 stable connect and response series do not mix", func(t *testing.T) {
		var metrics vaneMetrics
		for i := 0; i < 8; i++ {
			at := now.Add(time.Duration(i) * time.Second)
			metrics.observeConnect(at, 20*time.Millisecond)
			metrics.observeResponse(at, 120*time.Millisecond)
		}
		estimate := metrics.snapshot(now.Add(8 * time.Second)).jitter
		require.True(t, estimate.valid)
		require.InDelta(t, 0, estimate.value, 1e-9)
	})

	t.Run("JITTER-04 invalid samples do not advance tracker", func(t *testing.T) {
		var tracker vaneJitterTracker
		for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
			tracker.observeLatency(now, value)
		}
		require.Zero(t, tracker.samples)
		require.False(t, tracker.mean.fast.valid)
		require.False(t, tracker.deviation.fast.valid)
	})

	t.Run("JITTER-07 tracker evidence decays on the slow horizon", func(t *testing.T) {
		var tracker vaneJitterTracker
		tracker.observeLatency(now, 10)
		tracker.observeLatency(now, 30)
		fresh := tracker.estimate(now)
		old := tracker.estimate(now.Add(2*time.Hour + time.Second))
		require.True(t, fresh.valid)
		require.True(t, old.valid)
		require.Less(t, old.confidence, fresh.confidence)
	})
}

func TestVaneJitterScoring(t *testing.T) {
	t.Run("JITTER-05 five weights sum to one", func(t *testing.T) {
		for _, scene := range []vaneScene{vaneSceneDefault, vaneSceneInteractive, vaneSceneMedia, vaneSceneBulk} {
			c := vaneScoring(scene)
			require.InDelta(t, 1, c.failureWeight+c.connectWeight+c.responseWeight+c.throughputWeight+c.jitterWeight, 1e-12, scene.String())
		}
	})

	t.Run("JITTER-06 logarithmic cost anchors", func(t *testing.T) {
		require.Zero(t, vaneJitterCost(0, 3, 100))
		require.Zero(t, vaneJitterCost(3, 3, 100))
		require.Equal(t, 1.0, vaneJitterCost(100, 3, 100))
		require.InDelta(t, math.Log(10.0/3)/math.Log(100.0/3), vaneJitterCost(10, 3, 100), 1e-12)
	})

	t.Run("JITTER-07 jitter raises score monotonically", func(t *testing.T) {
		base := vaneMetricsSnapshot{
			failure:    vaneMetricEstimate{confidence: 1, valid: true},
			connect:    vaneMetricEstimate{value: math.Log(20), confidence: 1, valid: true},
			response:   vaneMetricEstimate{value: math.Log(60), confidence: 1, valid: true},
			throughput: vaneMetricEstimate{value: math.Log(10_000_000), confidence: 1, valid: true},
		}
		low, high := base, base
		low.jitter = vaneMetricEstimate{value: 3, confidence: 1, valid: true}
		high.jitter = vaneMetricEstimate{value: 30, confidence: 1, valid: true}
		require.Less(t, scoreVaneMetrics(vaneSceneMedia, low), scoreVaneMetrics(vaneSceneMedia, high))
	})

	t.Run("JITTER-08 equal mean stable connection ranks ahead", func(t *testing.T) {
		stable := vaneMetricsSnapshot{connect: vaneMetricEstimate{value: math.Log(20), confidence: 1, valid: true}, jitter: vaneMetricEstimate{value: 2, confidence: 1, valid: true}}
		spiky := stable
		spiky.jitter.value = 30
		ranked := rankVaneCandidates(vaneSceneInteractive, map[string]vaneMetricsSnapshot{"z-stable": stable, "a-spiky": spiky})
		require.Equal(t, []string{"z-stable", "a-spiky"}, candidateNames(ranked), "jitter must beat the lexical tie-break")
	})
}

func TestVaneJitterPersistence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	t.Run("JITTER-09 connect-only tracker round trips", func(t *testing.T) {
		var metrics vaneMetrics
		metrics.observeConnect(now, 60*time.Millisecond)
		metrics.observeConnect(now.Add(time.Second), 90*time.Millisecond)
		at := now.Add(time.Second)
		payload, err := json.Marshal(persistVaneMetrics(metrics, at))
		require.NoError(t, err)
		var persisted vanePersistedMetrics
		require.NoError(t, json.Unmarshal(payload, &persisted))
		// Isolate jitter: it can keep a restored node valid on its own.
		restored, valid, invalid := restoreVaneMetrics(vanePersistedMetrics{Jitter: persisted.Jitter}, at)
		require.True(t, valid)
		require.False(t, invalid)
		require.Equal(t, metrics.jitter.samples, restored.jitter.samples)
		require.Equal(t, persistVaneJitter(metrics.jitter), persistVaneJitter(restored.jitter))
		require.Equal(t, metrics.jitter.estimate(at), restored.jitter.estimate(at))
	})

	t.Run("JITTER-10 legacy payload without jitter restores empty", func(t *testing.T) {
		var persisted vanePersistedMetrics
		require.NoError(t, json.Unmarshal([]byte(`{"connect":{"fast":{"weight":2,"sum":6,"updatedAt":"2023-11-14T22:13:20Z","valid":true}}}`), &persisted))
		metrics, valid, invalid := restoreVaneMetrics(persisted, now)
		require.True(t, valid)
		require.False(t, invalid)
		require.True(t, metrics.snapshot(now).connect.valid)
		require.False(t, metrics.jitter.estimate(now).valid)
	})

	t.Run("JITTER-11 no samples omit the field", func(t *testing.T) {
		payload, err := json.Marshal(persistVaneMetrics(vaneMetrics{}, now))
		require.NoError(t, err)
		require.NotContains(t, string(payload), `"jitter"`)
	})

	t.Run("JITTER-12 inconsistent payloads are rejected", func(t *testing.T) {
		validLayer := vanePersistedDecayLayer{Weight: 1, Sum: 10, UpdatedAt: now, Valid: true}
		for _, persisted := range []*vanePersistedJitter{
			{Samples: 1},
			{Samples: 0, Mean: vanePersistedDualMetric{Fast: validLayer}},
			{Samples: -1},
		} {
			_, valid, invalid := restoreVaneJitter(persisted, now)
			require.False(t, valid)
			require.True(t, invalid)
		}
	})
}
