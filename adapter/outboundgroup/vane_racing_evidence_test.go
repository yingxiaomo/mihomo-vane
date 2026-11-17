package outboundgroup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func waitVaneRaceIdle(t *testing.T, group *Vane) {
	t.Helper()
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight && len(group.racingRuntime.activeTasks) == 0
	}, 2*time.Second, time.Millisecond)
}

func newVaneRacingEvidenceGroup(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *vaneTestProxy) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	gamma := newVaneTestProxy("gamma", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	return group, clock, alpha, beta, gamma
}

func seedVaneCapability(group *Vane, clock *vaneConnTestClock, proxy *vaneTestProxy, bps float64) {
	group.mu.Lock()
	lease := group.memberLeaseLocked(proxy.Name(), proxy.identity)
	group.mu.Unlock()
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{
		member: lease, lowerBoundBPS: bps, bytes: 4096, observedAt: clock.Now(),
	}
	group.racingRuntime.mu.Unlock()
}

func TestVaneRacingTargetEvidenceOutranksCapabilityAndProbing(t *testing.T) {
	group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 80_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	group.mu.Lock()
	betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()
	group.recordTargetEvidence(request.targetKey, betaLease, 9_000_000)
	seedVaneCapability(group, clock, gamma, 50_000_000)

	resultCh := make(chan vaneRaceResult, 1)
	scheduled, reason := group.scheduleMediaRace(request, func(result vaneRaceResult) { resultCh <- result })
	require.True(t, scheduled, reason)
	result := <-resultCh
	require.Equal(t, "beta", result.winner.name, "fresh real-target evidence must win before any probe")
	require.Equal(t, "target-evidence", result.source)
	require.Zero(t, probes.Load(), "a proven challenger must not consume probe budget")
	waitVaneRaceIdle(t, group)
}

func TestVaneRacingCapabilityCacheSkipsProbing(t *testing.T) {
	group, clock, _, _, gamma := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{valid: false, reason: "early-eof"}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	seedVaneCapability(group, clock, gamma, 50_000_000)

	resultCh := make(chan vaneRaceResult, 1)
	scheduled, reason := group.scheduleMediaRace(request, func(result vaneRaceResult) { resultCh <- result })
	require.True(t, scheduled, reason)
	result := <-resultCh
	require.Equal(t, "gamma", result.winner.name)
	require.Equal(t, "capability-cache", result.source)
	require.Zero(t, probes.Load(), "a fresh capability proof must not consume probe budget")
	waitVaneRaceIdle(t, group)
}

func TestVaneRacingCachedBelowRequiredSuppressesProbe(t *testing.T) {
	group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 80_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	seedVaneCapability(group, clock, beta, 1_000)
	seedVaneCapability(group, clock, gamma, 1_000)

	scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) { t.Fatal("a cached slow challenger must not win") })
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Zero(t, probes.Load(), "fresh cache entries must short-circuit probing")
	require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)
}

func TestVaneRacingProbeFailOpenReasons(t *testing.T) {
	payload := make([]byte, 32*1024)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/redirect":
			http.Redirect(writer, request, "https://elsewhere.invalid/file", http.StatusFound)
		case "/header-stall":
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		default:
			_, _ = writer.Write(payload)
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	trusted := &tls.Config{RootCAs: pool}

	t.Run("invalid port", func(t *testing.T) {
		endpoint, err := url.Parse("https://example.com:99999/file")
		require.NoError(t, err)
		result := probeVaneCapability(t.Context(), newVaneTestProxy("probe", true, true), endpoint, 1024)
		require.Equal(t, "invalid-port", result.reason)
	})

	t.Run("dial error", func(t *testing.T) {
		proxy := newVaneTestProxy("probe", true, true)
		proxy.dialErr = errors.New("dial refused")
		endpoint, err := url.Parse("https://example.com/file")
		require.NoError(t, err)
		result := probeVaneCapability(t.Context(), proxy, endpoint, 1024)
		require.Equal(t, "dial-error", result.reason)
	})

	t.Run("nil connection", func(t *testing.T) {
		endpoint, err := url.Parse("https://example.com/file")
		require.NoError(t, err)
		result := probeVaneCapability(t.Context(), newVaneTestProxy("probe", true, true), endpoint, 1024)
		require.Equal(t, "nil-connection", result.reason)
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		endpoint, err := url.Parse(server.URL + "/file")
		require.NoError(t, err)
		proxy := newVaneNetworkTestProxy("probe")
		result := probeVaneCapability(t.Context(), proxy, endpoint, 1024)
		require.Equal(t, "tls-error", result.reason)
	})

	t.Run("redirect is never followed", func(t *testing.T) {
		endpoint, err := url.Parse(server.URL + "/redirect")
		require.NoError(t, err)
		result := probeVaneCapabilityWithTLSConfig(t.Context(), newVaneNetworkTestProxy("probe"), endpoint, 1024, trusted)
		require.Equal(t, "redirect-disallowed", result.reason)
	})

	t.Run("header stall times out", func(t *testing.T) {
		endpoint, err := url.Parse(server.URL + "/header-stall")
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		result := probeVaneCapabilityWithTLSConfig(ctx, newVaneNetworkTestProxy("probe"), endpoint, 1024, trusted)
		require.False(t, result.valid)
		require.Contains(t, []string{"header-timeout", "read-timeout", "canceled", "response-error"}, result.reason)
	})
}
