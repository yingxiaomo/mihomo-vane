package outboundgroup

import (
	"context"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// This replay preserves the original selection fixture and pins the
// intentional score change from the fifth dimension (JITTER-P1-001).
func TestVaneRenameBehaviorReplay(t *testing.T) {
	clock := newVaneConnTestClock()
	a := newVaneTestProxy("alpha", true, true)
	b := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 100, time.Hour, a, b)
	defer group.Close()
	meta := &C.Metadata{NetWork: C.TCP, Host: "replay.example", DstPort: 443}
	choices := []string{group.pick(meta, vaneTransportTCP, true, true).Name()}
	for i := 0; i < 12; i++ {
		group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 900*time.Millisecond)
		group.observeConnect("beta", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
		clock.Advance(time.Second)
	}
	choices = append(choices, group.pick(meta, vaneTransportTCP, true, true).Name())
	group.recordDialFailure(context.Background(), meta, vaneTransportTCP, b, errors.New("replay failure"), clock.Now())
	choices = append(choices, group.pick(meta, vaneTransportTCP, true, true).Name())
	// STICKY: the per-host sticky choice lasts vaneStickyTTL. After it expires
	// the pick re-ranks from scratch, so the faster connector (beta) wins.
	clock.Advance(2 * vaneStickyTTL)
	choices = append(choices, group.pick(meta, vaneTransportTCP, true, true).Name())
	scores := []int64{}
	var metrics vaneMetrics
	for i := 0; i < 16; i++ {
		metrics.observeFailure(clock.Now(), i%7 == 0)
		metrics.observeConnect(clock.Now(), 40*time.Millisecond)
		metrics.observeResponse(clock.Now(), 70*time.Millisecond)
		metrics.observeThroughput(clock.Now(), 8000000)
		clock.Advance(time.Second)
	}
	scores = append(scores, scoreVaneMetricsFlat(metrics.snapshot(clock.Now())))
	// D batch weight table: connect is 0.08 of interactive and 0.04 of default,
	// and this fixture varies only connect latency (900ms vs 20ms). That is a
	// ~2.9% score difference, below the 5% strict margin, so the anchor is kept.
	// The fixture now pins that "better connect alone does not justify a switch".
	require.Equal(t, []string{"alpha", "alpha", "alpha", "beta"}, choices)
	// Absolute scores shift by the neutral profile blend; the ordering is the contract.
	require.Equal(t, []int64{346692}, scores)
}

// TestVaneStickyYieldsToAFasterNode keeps the sticky window from turning into
// liveness: a node that is still reachable but has fallen well behind on
// throughput must lose the host on the next pick, or the group degrades to
// "any node that answers stays".
func TestVaneStickyYieldsToAFasterNode(t *testing.T) {
	clock := newVaneConnTestClock()
	a := newVaneTestProxy("alpha", true, true)
	b := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 100, time.Hour, a, b)
	defer group.Close()
	meta := &C.Metadata{NetWork: C.TCP, Host: "rr1---sn-gap.googlevideo.com", DstPort: 443}

	require.Equal(t, "alpha", group.pick(meta, vaneTransportTCP, true, true).Name())

	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 200*time.Millisecond)
	group.observeConnect("beta", vaneTransportTCP, clock.Now(), 100*time.Millisecond)
	group.mu.Lock()
	group.nodes["alpha"].tcp.observeThroughput(clock.Now(), 2_000_000)
	group.nodes["beta"].tcp.observeThroughput(clock.Now(), 60_000_000)
	group.mu.Unlock()

	clock.Advance(10 * time.Second)
	require.Equal(t, "beta", group.pick(meta, vaneTransportTCP, true, false).Name(),
		"a sticky node that fell behind the best by more than the margin must lose the host")
}

// TestVaneSegmentGapsKeepTheSameExit pins the sticky window to the player's
// behaviour rather than to a wall clock: a player drops and rebuilds its
// connection while the buffer refills, and every rebuild used to re-pick from
// the current scores. A gap shorter than vaneStickyTTL must land on the exit the
// host was already using, even when another node has become the better
// connector; only a gap past the window may re-rank.
//
// Each gap is measured from the moment the host was pinned, not from the
// previous pick: a player's gaps overlap the same buffer refill, they do not
// chain into one longer silence.
func TestVaneSegmentGapsKeepTheSameExit(t *testing.T) {
	clock := newVaneConnTestClock()
	a := newVaneTestProxy("alpha", true, true)
	b := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 100, time.Hour, a, b)
	defer group.Close()
	meta := &C.Metadata{NetWork: C.TCP, Host: "rr1---sn-gap.googlevideo.com", DstPort: 443}

	require.Equal(t, "alpha", group.pick(meta, vaneTransportTCP, true, true).Name())
	base := clock.Now()

	// beta becomes the better connector on the path both picks are ranked on.
	group.observeConnect("alpha", vaneTransportTCP, base, 900*time.Millisecond)
	group.observeConnect("beta", vaneTransportTCP, base, 100*time.Millisecond)

	for _, gap := range []time.Duration{10 * time.Second, 30 * time.Second, 50 * time.Second} {
		clock.Advance(base.Add(gap).Sub(clock.Now()))
		require.Equal(t, "alpha", group.pick(meta, vaneTransportTCP, true, false).Name(),
			"a buffering gap of %s must not re-pick", gap)
	}

	// Past the window the faster connector is allowed to take over.
	clock.Advance(base.Add(vaneStickyTTL + time.Second).Sub(clock.Now()))
	require.Equal(t, "beta", group.pick(meta, vaneTransportTCP, true, false).Name())
}
