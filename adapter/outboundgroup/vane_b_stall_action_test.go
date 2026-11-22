package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// STALL-ACTION-01: a stalled flow is fed synthetic windows by the watchdog and
// never reads again. Its policy action must run immediately instead of being
// parked for a read that never comes.
func TestVaneSyntheticWindowActionIsImmediate(t *testing.T) {
	cases := []struct {
		name   string
		sample vaneThroughputObservation
		want   bool
	}{
		{"delivered", vaneThroughputObservation{Delivered: true}, true},
		{"synthetic-stall", vaneThroughputObservation{BitsPerSecond: 1, synthetic: true}, true},
		{"undelivered-real", vaneThroughputObservation{BitsPerSecond: 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, vaneActionIsImmediate(tc.sample))
		})
	}
}

// STALL-ACTION-02: the watchdog no longer discards the plan a stalled flow
// produces, and it is submitted as an immediate action.
func TestVaneStalledFlowSubmitsItsPlan(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	t.Cleanup(func() { _ = group.Close() })
	seedChain01Traffic(t, group, "beta", clock.Now(), 40_000_000)

	metadata := &C.Metadata{Host: "rr-stall.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	flow := newVaneMediaFlow(group, alpha.Name(), metadata)
	require.NotNil(t, flow)
	var delivered []bool
	flow.setPolicySubmitter(func(_ vanePolicyAction, immediate bool) { delivered = append(delivered, immediate) })

	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 8 << 20, Age: 20 * time.Second, Delivered: true,
	})
	for i := 0; i < 4 && len(delivered) == 0; i++ {
		clock.Advance(vaneMediaStallSilence + 10*time.Second)
		flow.observeSyntheticStall(clock.Now())
	}
	require.NotEmpty(t, delivered, "a stalled flow past the low-window line must still switch")
	require.True(t, delivered[0], "a synthetic window's action is immediate, never parked")
}
