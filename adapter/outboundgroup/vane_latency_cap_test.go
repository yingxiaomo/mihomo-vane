package outboundgroup

import (
	"context"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// latency-cap: nodes whose media-window RTT EMA exceeds vaneLatencyHardCapMs
// are not ranked, unless that would empty the pool.

func newLatencyCapGroup(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *C.Metadata) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	metadata := &C.Metadata{Host: "rr-latency.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	return group, clock, alpha, beta, metadata
}

// seedLatencyCapNodes gives alpha a clean loss profile and beta 5%, so alpha
// wins on more than latency alone: a test that only differs in RTT would pass
// with the cap deleted.
func seedLatencyCapNodes(t *testing.T, group *Vane, clock *vaneConnTestClock, alpha, beta *vaneTestProxy,
	alphaLatency, betaLatency float64, alphaAt time.Time) {
	t.Helper()
	now := clock.Now()
	group.mu.Lock()
	defer group.mu.Unlock()
	group.learning.mu.Lock()
	defer group.learning.mu.Unlock()
	a := group.ensureProxyNodeLocked(alpha, now)
	b := group.ensureProxyNodeLocked(beta, now)
	if alphaLatency > 0 {
		a.latencyMs, a.latencySamples, a.latencyAt = alphaLatency, 10, alphaAt
	}
	b.latencyMs, b.latencySamples, b.latencyAt = betaLatency, 10, now
	a.cumulSent, a.cumulRetrans, a.cumulAt = 2000, 0, now
	b.cumulSent, b.cumulRetrans, b.cumulAt = 2000, 100, now
}

// LATENCY-CAP-01: the slower node is dropped even though it wins on loss.
func TestVaneLatencyCapExcludesOverCap(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 400, 100, clock.Now())

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "beta", decision.proxy.Name())
	require.Equal(t, 1, countVaneEvents(group, "latency-cap-excluded", ""))
}

// LATENCY-CAP-02: every candidate over the cap -> fail open, slowest dropped.
func TestVaneLatencyCapFailOpenWhenAllCapped(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 400, 500, clock.Now())

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	occurrences := 0
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "latency-cap-excluded" {
			occurrences = event.Occurrences
		}
	}
	require.Equal(t, 2, occurrences)
}

// LATENCY-CAP-03: a node with no latency samples is never capped.
func TestVaneLatencyCapIgnoresMissingSamples(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 0, 100, clock.Now())

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.Zero(t, countVaneEvents(group, "latency-cap-excluded", ""))
}

// LATENCY-CAP-04: exactly at the cap is allowed (">", not ">=").
func TestVaneLatencyCapBoundaryAllowsExactlyCap(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 350, 100, clock.Now())

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.Zero(t, countVaneEvents(group, "latency-cap-excluded", ""))
}

// LATENCY-CAP-05: stale samples are no evidence and never cap.
func TestVaneLatencyCapIgnoresStaleSamples(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 400, 100, clock.Now().Add(-8*24*time.Hour))

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.Zero(t, countVaneEvents(group, "latency-cap-excluded", ""))
}

// LATENCY-CAP-06: nobody over the cap -> normal ranking.
func TestVaneLatencyCapAllowsUnderCap(t *testing.T) {
	group, clock, alpha, beta, metadata := newLatencyCapGroup(t)
	seedLatencyCapNodes(t, group, clock, alpha, beta, 100, 200, clock.Now())

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.Zero(t, countVaneEvents(group, "latency-cap-excluded", ""))
}
