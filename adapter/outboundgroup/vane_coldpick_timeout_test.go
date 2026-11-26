package outboundgroup

import (
	"context"
	"net/url"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// probe-timeout: a read-timeout probe is valid but its burst average is not
// cold-pick evidence. These tests drive the real pick path; only the probe
// result is injected.

func coldPickProbeCached(group *Vane, name string) bool {
	group.mu.Lock()
	defer group.mu.Unlock()
	for member := range group.racingRuntime.capabilities {
		if member.name == name {
			return true
		}
	}
	return false
}

func coldPickProbeReason(t *testing.T, group *Vane) string {
	t.Helper()
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "pick-probe-selected" {
			return event.Reason
		}
	}
	t.Fatal("no pick-probe-selected event")
	return ""
}

// PROBE-TIMEOUT-01: both probes read-timeout -> ranking fallback, nothing cached.
func TestVaneColdPickProbeTimeoutBothExcluded(t *testing.T) {
	group, _, _, _, metadata := newColdPickGroupForTest(t, vaneSwitchObserve)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{valid: true, reason: "read-timeout", bytes: 2_800_000, duration: 4 * time.Second, lowerBoundBPS: 5_660_000}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "ranked-fallback", coldPickProbeReason(t, group))
	require.NotEmpty(t, decision.proxy.Name())
	require.False(t, coldPickProbeCached(group, "alpha"))
	require.False(t, coldPickProbeCached(group, "beta"))
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(2), snapshot.Counters.PickProbeCount, "timeouts are probes too")
	require.Positive(t, snapshot.Counters.PickProbeBytes, "a timed-out probe still spent bytes")
}

// PROBE-TIMEOUT-02: a read-timeout burst (5.66M) must lose to a clean cap-hit (4M).
func TestVaneColdPickProbeTimeoutLosesToCleanProbe(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneSwitchObserve)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		if proxy.Name() == alphaName {
			return vaneProbeResult{valid: true, reason: "read-timeout", bytes: 2_830_000, duration: 4 * time.Second, lowerBoundBPS: 5_660_000}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 4_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", decision.proxy.Name())
	require.Equal(t, "probe", coldPickProbeReason(t, group))
	require.False(t, coldPickProbeCached(group, "alpha"), "a read timeout must not enter the capability cache")
	require.True(t, coldPickProbeCached(group, "beta"))
}

// PROBE-TIMEOUT-03: a zero-byte read timeout is already invalid; unchanged.
func TestVaneColdPickProbeTimeoutZeroBytesUnchanged(t *testing.T) {
	group, _, _, _, metadata := newColdPickGroupForTest(t, vaneSwitchObserve)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{valid: false, reason: "read-timeout"}
	}

	group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "ranked-fallback", coldPickProbeReason(t, group))
	require.False(t, coldPickProbeCached(group, "alpha"))
	require.False(t, coldPickProbeCached(group, "beta"))
}

// PROBE-TIMEOUT-04: clean probes are unaffected — faster wins, both cached.
func TestVaneColdPickProbeTimeoutCleanProbesStillWin(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneSwitchObserve)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		if proxy.Name() == alphaName {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 8_000_000, capHit: true}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 4_000_000, capHit: true}
	}

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.True(t, coldPickProbeCached(group, "alpha"))
	require.True(t, coldPickProbeCached(group, "beta"))
}

// PROBE-TIMEOUT-05: the diagnostic names the exclusion instead of claiming success.
func TestVaneColdPickProbeTimeoutDiagnosticKind(t *testing.T) {
	group, _, alpha, _, metadata := newColdPickGroupForTest(t, vaneSwitchObserve)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	alphaName := alpha.Name()
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		if proxy.Name() == alphaName {
			return vaneProbeResult{valid: true, reason: "read-timeout", bytes: 2_830_000, duration: 4 * time.Second, lowerBoundBPS: 5_660_000}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 4_000_000, capHit: true}
	}

	group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, 1, countVaneEvents(group, "pick-probe-timeout", ""))
	require.Equal(t, 1, countVaneEvents(group, "pick-probe-success", ""))
}
