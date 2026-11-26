package outboundgroup

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func vaneP5Time(hour int) time.Time {
	// Local wall clock so the hourly bucket lands deterministically.
	return time.Date(2026, 11, 18, hour, 0, 0, 0, time.Local)
}

// P5-P10-001: the 32-sample ring feeds the 10th percentile over a 6h window;
// expired samples drop, illegal samples never enter, and reads stay pure.
func TestVaneP5Percentile10(t *testing.T) {
	now := vaneP5Time(10)
	var p vaneP5
	_, ok := p.percentile10(now)
	require.False(t, ok, "an empty ring has no percentile")

	// 31 samples at 100..130 Mbps: p10 index floor(0.1*30) = 3 → 103.
	for index := 0; index < 31; index++ {
		p.observe(now, float64(100+index)*1_000_000)
	}
	p10, ok := p.percentile10(now)
	require.True(t, ok)
	require.Equal(t, 103*1_000_000.0, p10)

	// The 32nd sample evicts the oldest (100); p10 index floor(0.1*31) = 3 → 103 still.
	p.observe(now, 131*1_000_000)
	p10, _ = p.percentile10(now)
	require.Equal(t, 103*1_000_000.0, p10)

	// Reads are pure: a second read returns the same value.
	again, _ := p.percentile10(now)
	require.Equal(t, p10, again)

	// Expired samples (older than 6h) drop out of the read.
	stale := now.Add(-vaneP5RingWindow - time.Minute)
	fresh := &vaneP5{}
	fresh.observe(stale, 999*1_000_000)
	fresh.observe(now, 10*1_000_000)
	p10, _ = fresh.percentile10(now)
	require.Equal(t, 10*1_000_000.0, p10, "the stale sample must not participate")

	// Illegal samples are rejected before touching any statistic.
	guard := &vaneP5{}
	guard.observe(now, 5*1_000_000)
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -1} {
		guard.observe(now, bad)
	}
	require.Equal(t, 1, guard.ringLen, "NaN/Inf/<=0 never enter the ring")
	peak, ok := guard.peak(now)
	require.True(t, ok)
	require.Equal(t, 5*1_000_000.0, peak)
}

// P5-PEAK-001: the peak tracks the maximum within 24h and expires afterwards.
func TestVaneP5Peak(t *testing.T) {
	now := vaneP5Time(10)
	var p vaneP5
	p.observe(now, 10*1_000_000)
	peak, ok := p.peak(now)
	require.True(t, ok)
	require.Equal(t, 10*1_000_000.0, peak)

	p.observe(now.Add(time.Minute), 5*1_000_000)
	peak, _ = p.peak(now.Add(time.Minute))
	require.Equal(t, 10*1_000_000.0, peak, "a lower sample keeps the peak")

	p.observe(now.Add(2*time.Minute), 50*1_000_000)
	peak, _ = p.peak(now.Add(2 * time.Minute))
	require.Equal(t, 50*1_000_000.0, peak)

	// Beyond 24h the peak reads as nonexistent.
	_, ok = p.peak(now.Add(25 * time.Hour))
	require.False(t, ok)

	// The next sample after expiry becomes the new peak even though it is lower.
	p.observe(now.Add(25*time.Hour+time.Minute), 20*1_000_000)
	peak, ok = p.peak(now.Add(25 * time.Hour).Add(time.Minute))
	require.True(t, ok)
	require.Equal(t, 20*1_000_000.0, peak)
}

// P5-HOURLY-001: each local hour keeps its own count-decaying EMA, first
// sample = estimate, same alpha shape as the loss EMA.
func TestVaneP5HourlyProfile(t *testing.T) {
	now := vaneP5Time(10)
	var p vaneP5
	p.observe(now, 10*1_000_000)
	profile := p.hourProfile()
	require.Equal(t, 10*1_000_000.0, profile[10])
	require.Zero(t, profile[11], "untouched buckets stay zero")

	p.observe(now.Add(time.Minute), 20*1_000_000)
	profile = p.hourProfile()
	alpha := vaneP5AlphaBase / (1 + vaneP5AlphaDecay)
	require.InDelta(t, 10*1_000_000.0+alpha*(20*1_000_000.0-10*1_000_000.0), profile[10], 1e-6)

	// A different hour lands in its own bucket.
	p.observe(vaneP5Time(11), 30*1_000_000)
	profile = p.hourProfile()
	require.Equal(t, 30*1_000_000.0, profile[11])
}

// P5-DIAG-001: P5Nodes only lists nodes with throughput samples and never
// mutates their state.
func TestVaneP5Diagnostics(t *testing.T) {
	group, clock, alpha, _, _ := newVaneRacingEvidenceGroup(t)
	group.mu.Lock()
	group.ensureProxyNodeLocked(alpha, clock.Now())
	alphaState := group.nodes[alpha.Name()]
	group.mu.Unlock()
	require.NotNil(t, alphaState)

	// No throughput yet: the node must not appear.
	snapshot := group.VaneDiagnostics()
	require.Empty(t, snapshot.Runtime.P5Nodes)

	// Feed raw samples through the observe path for TCP only. The observer
	// takes its own locks — call it bare.
	group.observeThroughputEpochIdentity(alpha.Name(), alpha.identity, alphaState.epoch, vaneTransportTCP, clock.Now(), 40*1_000_000)
	group.observeThroughputEpochIdentity(alpha.Name(), alpha.identity, alphaState.epoch, vaneTransportTCP, clock.Now().Add(time.Minute), 60*1_000_000)

	snapshot = group.VaneDiagnostics()
	node, ok := snapshot.Runtime.P5Nodes[alpha.Name()]
	require.True(t, ok, "a node with throughput samples must appear")
	require.NotZero(t, node.TCP.P10BPS)
	require.Equal(t, 60*1_000_000.0, node.TCP.PeakBPS)
	require.Len(t, node.TCP.Hours, vaneP5BucketCount)
	require.Zero(t, node.UDP.P10BPS, "udp transport without samples stays empty")
	require.Zero(t, node.UDP.PeakBPS)

	// The read must not change the ring: repeat and compare.
	again := group.VaneDiagnostics()
	require.Equal(t, node.TCP.P10BPS, again.Runtime.P5Nodes[alpha.Name()].TCP.P10BPS)
}

// P5-PERSIST-001: the profile survives a persist→restore round trip, expired
// samples drop, bucket counts halve once, old snapshots without the field
// restore empty, and P5 never decides node validity.
func TestVaneP5Persistence(t *testing.T) {
	now := vaneP5Time(10)

	t.Run("round trip keeps p10, peak and buckets", func(t *testing.T) {
		// Anchor 20 minutes past the hour so every sample sits in the past:
		// the restore must reject anything beyond now+skew by contract.
		now := vaneP5Time(10).Add(20 * time.Minute)
		var source vaneP5
		for index := 0; index < 20; index++ {
			source.observe(now.Add(-time.Duration(20-index)*time.Minute), float64(40+index)*1_000_000)
		}
		source.observe(now.Add(-time.Minute), 80*1_000_000) // peak

		restored := restoreVaneP5(persistVaneP5(&source, now), now)
		p10, ok := restored.percentile10(now)
		require.True(t, ok)
		expected, _ := source.percentile10(now)
		require.Equal(t, expected, p10)
		peak, ok := restored.peak(now)
		require.True(t, ok)
		require.Equal(t, 80*1_000_000.0, peak)
		require.Equal(t, source.hourProfile(), restored.hourProfile())
		// Bucket counts halve once: hour 10 held 21 samples.
		require.Equal(t, int64(10), restored.buckets[10].samples)
	})

	t.Run("expired samples drop at persist, future skew drops at restore", func(t *testing.T) {
		var source vaneP5
		source.observe(now.Add(-vaneP5RingWindow-time.Hour), 5*1_000_000)
		source.observe(now, 50*1_000_000)
		persisted := persistVaneP5(&source, now)
		require.Len(t, persisted.Ring, 1, "the expired sample must not persist")

		restored := restoreVaneP5(persisted, now)
		require.Equal(t, 1, restored.ringLen)
		p10, ok := restored.percentile10(now)
		require.True(t, ok)
		require.Equal(t, 50*1_000_000.0, p10)

		future := &vanePersistedP5{Ring: []vanePersistedP5RingSample{
			{BPS: 1, At: now.Add(2 * vaneLearningFutureSkew)},
			{BPS: 2, At: time.Time{}},
			{BPS: -3, At: now},
			{BPS: math.NaN(), At: now},
		}}
		empty := restoreVaneP5(future, now)
		require.Zero(t, empty.ringLen, "future-skewed, zero-time and illegal samples all drop")
	})

	t.Run("bad buckets clear, sane buckets halve", func(t *testing.T) {
		persisted := &vanePersistedP5{
			BucketEMA: [vaneP5BucketCount]float64{10: 1_000_000, 20: -1, 21: math.NaN()},
			BucketN:   [vaneP5BucketCount]int64{10: 64, 20: 5, 21: 5},
		}
		restored := restoreVaneP5(persisted, now)
		require.Equal(t, 1_000_000.0, restored.buckets[10].ema)
		require.Equal(t, int64(32), restored.buckets[10].samples)
		require.Zero(t, restored.buckets[20].ema, "a negative estimate clears its bucket")
		require.Zero(t, restored.buckets[20].samples)
		require.Zero(t, restored.buckets[21].ema)
	})

	t.Run("old snapshots without p5 restore empty", func(t *testing.T) {
		legacy := vanePersistedMetrics{}
		metrics, _, _ := restoreVaneMetrics(legacy, now)
		require.False(t, metrics.p5.hasData())
		require.Zero(t, metrics.p5.peakBPS)
	})

	t.Run("p5 never decides node validity", func(t *testing.T) {
		node := vanePersistedNode{
			Name: "alpha", Identity: "test:alpha", LastSeen: now,
			TCP: vanePersistedMetrics{P5: persistVaneP5(&vaneP5{ringLen: 1, peakBPS: 9, peakAt: now}, now)},
		}
		_, ok, invalid := restoreVaneNode(node, now)
		require.False(t, ok, "a node kept alive only by P5 must not resurrect")
		require.False(t, invalid)
	})
}
