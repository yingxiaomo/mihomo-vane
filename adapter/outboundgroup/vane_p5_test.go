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
// sample = estimate, same alpha shape as the B2 loss EMA.
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
