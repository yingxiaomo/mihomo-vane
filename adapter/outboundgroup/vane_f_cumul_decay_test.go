package outboundgroup

import (
	"math"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// cumulDecayGroup builds a group whose alpha node already exists, so the
// cumulative-loss bookkeeping has somewhere to land.
func cumulDecayGroup(t *testing.T) (*Vane, *vaneConnTestClock) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	t.Cleanup(func() { _ = group.Close() })
	metadata := &C.Metadata{Host: "cumul.example", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, true, true)
	return group, clock
}

func bookCumul(t *testing.T, group *Vane, sent, retrans uint64) {
	t.Helper()
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	group.recordCumulativeLossIdentity("alpha", identity, epoch, vaneConnectionCloseObservation{
		SegsOut: sent, RetransSegs: retrans, LossSupported: true,
	})
}

func cumulState(group *Vane) (sent, retrans uint64, at time.Time) {
	group.mu.Lock()
	defer group.mu.Unlock()
	state := group.nodes["alpha"]
	return state.cumulSent, state.cumulRetrans, state.cumulAt
}

// CUMUL-EXP-01: within the window the old counters decay exponentially.
func TestVaneCumulDecayWithinWindow(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 900)
	clock.Advance(3 * 24 * time.Hour)
	bookCumul(t, group, 500, 0)

	sent, retrans, _ := cumulState(group)
	require.Equal(t, uint64(7014), sent)
	require.Equal(t, uint64(586), retrans)
	group.mu.Lock()
	rate, ok := group.nodes["alpha"].cumulLossRate(clock.Now())
	group.mu.Unlock()
	require.True(t, ok)
	require.InDelta(t, 0.08359, rate, 5e-4)
}

// CUMUL-EXP-02: exactly one window of silence voids the old counters, and the
// new booking is still valid evidence of zero loss.
func TestVaneCumulDecayAtWindowBoundary(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 900)
	clock.Advance(vaneProfileAgeReset)
	bookCumul(t, group, 500, 0)

	sent, retrans, _ := cumulState(group)
	require.Equal(t, uint64(500), sent)
	require.Equal(t, uint64(0), retrans)
	group.mu.Lock()
	rate, ok := group.nodes["alpha"].cumulLossRate(clock.Now())
	group.mu.Unlock()
	require.True(t, ok)
	require.InDelta(t, 0, rate, 1e-9)
}

// CUMUL-EXP-03: a clock rollback must not inflate the counters.
func TestVaneCumulDecayClockRollback(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 900)
	group.mu.Lock()
	group.nodes["alpha"].cumulAt = clock.Now().Add(7 * 24 * time.Hour)
	group.mu.Unlock()
	bookCumul(t, group, 10, 0)

	sent, retrans, _ := cumulState(group)
	require.Equal(t, uint64(10_010), sent)
	require.Equal(t, uint64(900), retrans)
}

// CUMUL-EXP-04: the first booking has no history to decay.
func TestVaneCumulDecayFirstBooking(t *testing.T) {
	group, _ := cumulDecayGroup(t)
	bookCumul(t, group, 100, 2)
	sent, retrans, _ := cumulState(group)
	require.Equal(t, uint64(100), sent)
	require.Equal(t, uint64(2), retrans)
}

// CUMUL-EXP-05: eight days of silence voids the pair before the new booking.
func TestVaneCumulDecayPastWindow(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 900)
	clock.Advance(8 * 24 * time.Hour)
	bookCumul(t, group, 500, 0)

	sent, retrans, _ := cumulState(group)
	require.Equal(t, uint64(500), sent)
	require.Equal(t, uint64(0), retrans)
}

// CUMUL-EXP-06: repeated booking rounds instead of truncating; truncation
// erodes ~10% of the counters over a thousand sockets.
func TestVaneCumulDecayRepeatedBooking(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 0)
	for i := 0; i < 1000; i++ {
		clock.Advance(time.Second)
		bookCumul(t, group, 10, 0)
	}
	sent, _, _ := cumulState(group)
	require.InDelta(t, 19975, float64(sent), 100)
}

// CUMUL-EXP-07: decay plus fresh traffic dilutes a lossy history below the 5%
// gate.
func TestVaneCumulDecayDilutesLossyHistory(t *testing.T) {
	group, clock := cumulDecayGroup(t)
	bookCumul(t, group, 10_000, 900)
	clock.Advance(6 * 24 * time.Hour)
	bookCumul(t, group, 4000, 0)

	group.mu.Lock()
	rate, ok := group.nodes["alpha"].cumulLossRate(clock.Now())
	group.mu.Unlock()
	require.True(t, ok)
	require.InDelta(t, 0.04633, rate, 2e-3)
	require.Less(t, rate, vaneDefaultMediaHighLossRate)
}

// FRESH-FUTURE-01: a future timestamp is not fresh.
func TestVaneProfileFutureTimestampIsStale(t *testing.T) {
	now := time.Now()
	require.False(t, (&vaneNodeState{}).profileFresh(now, now.Add(time.Hour)))
	require.True(t, (&vaneNodeState{}).profileFresh(now, now.Add(-time.Hour)))
}

// FRESH-FUTURE-02: a future LatencyAt is not restored.
func TestVaneRestoreFutureLatency(t *testing.T) {
	now := time.Now()
	state := &vaneNodeState{}
	_, _ = restoreVaneProfile(state, vanePersistedNode{
		Name: "beta", Identity: "test:beta", LastSeen: now,
		LatencyMs: 55, LatencySamples: 4, LatencyAt: now.Add(time.Hour),
	}, now)
	require.Zero(t, state.latencySamples)
	require.False(t, state.latencyEstimate(now).valid)
}

// FRESH-FUTURE-03: a future CumulObservedAt is not restored.
func TestVaneRestoreFutureCumulativeLoss(t *testing.T) {
	now := time.Now()
	node, _, _ := restoreVaneNode(vanePersistedNode{
		Name: "beta", Identity: "test:beta", LastSeen: now,
		SuccessCount: 2, CountersAt: now,
		CumulSent: 10_000, CumulRetrans: 900,
		CumulObservedAt: now.Add(time.Hour),
	}, now)
	require.NotNil(t, node)
	require.Zero(t, node.cumulSent)
	require.Zero(t, node.cumulRetrans)
}

// FRESH-FUTURE-05: a node stamped in the future is not adopted by selection.
func TestVaneSelectDropsFutureNode(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	defer group.Close()

	key := vaneLearningNodeKey("alpha", "test:alpha")
	group.mu.Lock()
	group.learningGeneration = group.learning.generation
	group.learning.nodes[key] = &vaneNodeState{
		name: "alpha", identity: "test:alpha", lastObservedAt: clock.Now().Add(2 * time.Hour),
		cumulSent: 999_999,
	}
	group.mu.Unlock()

	metadata := &C.Metadata{Host: "future.example", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, true, true)

	// Selection may rebuild a clean record at the same key; what it must never do
	// is adopt the 999_999-segment ghost that claims to be from the future.
	group.mu.Lock()
	state := group.nodes["alpha"]
	group.mu.Unlock()
	if state != nil {
		require.Zero(t, state.cumulSent)
	}
}

// FRESH-FUTURE-04: a node stamped in the future is pruned instead of living
// forever.
func TestVanePruneFutureLastSeen(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	defer group.Close()

	group.mu.Lock()
	group.learningGeneration = group.learning.generation
	group.learning.nodes["ghost"] = &vaneNodeState{
		name: "ghost", identity: "ghost:1", lastObservedAt: clock.Now().Add(2 * time.Hour),
	}
	group.pruneLocked(clock.Now(), nil)
	_, exists := group.learning.nodes["ghost"]
	group.mu.Unlock()
	require.False(t, exists)
}

// H2: a zero RTT with samples is corrupt, not a valid 0ms reading.
func TestVaneRestoreZeroLatencyWithSamplesIsInvalid(t *testing.T) {
	now := time.Now()
	state := &vaneNodeState{}
	_, invalid := restoreVaneProfile(state, vanePersistedNode{
		Name: "beta", Identity: "test:beta", LastSeen: now,
		LatencyMs: 0, LatencySamples: 4, LatencyAt: now,
	}, now)
	require.True(t, invalid)
	require.False(t, state.latencyEstimate(now).valid)
	require.Less(t, math.Abs(0), 1e-9)
}
