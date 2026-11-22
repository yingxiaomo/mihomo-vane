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
	for _, scene := range []vaneScene{vaneSceneDefault, vaneSceneInteractive, vaneSceneMedia, vaneSceneBulk} {
		scores = append(scores, scoreVaneMetrics(scene, metrics.snapshot(clock.Now())))
	}
	require.Equal(t, []string{"alpha", "beta", "alpha", "beta"}, choices)
	// Absolute scores shift by the neutral profile blend; the ordering is the contract.
	require.Equal(t, []int64{215764, 157968, 227451, 444065}, scores)
}
