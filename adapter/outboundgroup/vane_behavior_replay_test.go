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
	// STICKY: the per-host sticky choice lasts 60s. After it expires the
	// pick re-ranks from scratch, so the faster connector (beta) wins.
	clock.Advance(2 * time.Minute)
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
