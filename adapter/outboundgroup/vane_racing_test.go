package outboundgroup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type vaneNetworkTestProxy struct {
	*vaneTestProxy
	dials atomic.Int32
}

func newVaneNetworkTestProxy(name string) *vaneNetworkTestProxy {
	return &vaneNetworkTestProxy{vaneTestProxy: newVaneTestProxy(name, true, true)}
}

func (p *vaneNetworkTestProxy) Adapter() C.ProxyAdapter { return p }
func (p *vaneNetworkTestProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.dials.Add(1)
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(raw, p), nil
}

func configureVaneRacingForTest(t *testing.T, group *Vane, mode vaneRacingMode) {
	t.Helper()
	enabled := mode == vaneRacingOn
	config, err := newVaneRacingConfig(VaneOption{Vane: &enabled})
	require.NoError(t, err)
	group.racing = config
}

// RACE-CONFIG-001: omitted means enabled; false is diagnostic-only.
func TestVaneRacingConfig(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{}, fallback, nil)
	require.NoError(t, err)
	require.Equal(t, vaneRacingOn, group.racing.mode)
	require.Equal(t, "unknown", vaneRacingMode(255).String())
	require.Equal(t, vaneDefaultRacingURL, group.racing.url.String())
	require.Equal(t, int64(64*1024*1024), group.racing.budgetBytesHour)

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			configured, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{
				Vane: &enabled, RacingURL: "https://example.com/download",
			}, fallback, nil)
			require.NoError(t, err)
			require.Equal(t, int64(64*1024*1024), configured.racing.budgetBytesHour)
		})
	}
	for _, option := range []VaneOption{
		{RacingURL: "http://example.com/file"},
		{RacingURL: "https://user:pass@example.com/file"},
		{RacingURL: "https:///missing-host"},
	} {
		_, err := NewVane(GroupCommonOption{Name: "vane"}, option, fallback, nil)
		require.Error(t, err)
	}

	proxyMap := map[string]C.Proxy{
		"COMPATIBLE": A.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "COMPATIBLE", Type: C.Compatible})),
		"fallback":   fallback,
		"alpha":      newVaneTestProxy("alpha", true, true),
	}
	parsed, err := ParseProxyGroup(map[string]any{
		"name": "vane-racing", "type": "vane", "proxies": []string{"alpha"}, "empty-fallback": "fallback",
		"vane": false, "racing-url": "https://example.com/probe",
	}, proxyMap, map[string]P.ProxyProvider{}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, vaneRacingShadow, parsed.(*Vane).racing.mode)
	require.Equal(t, int64(64*1024*1024), parsed.(*Vane).racing.budgetBytesHour)
}

// RACE-PROBE-001: probe byte/time boundaries are repeatable and charge real bytes.
func TestVaneRacingProbe(t *testing.T) {
	payload := make([]byte, 128*1024)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/cap":
			_, _ = writer.Write(payload)
		case "/early":
			_, _ = writer.Write(payload[:16*1024])
		case "/zero":
			return
		case "/status":
			writer.WriteHeader(http.StatusServiceUnavailable)
		case "/slow":
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: pool}
	proxy := newVaneNetworkTestProxy("probe")
	parse := func(path string) *url.URL {
		endpoint, err := url.Parse(server.URL + path)
		require.NoError(t, err)
		return endpoint
	}

	result := probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse("/cap"), 64*1024, tlsConfig)
	require.True(t, result.valid)
	require.True(t, result.capHit)
	require.Equal(t, int64(64*1024), result.bytes)
	require.Positive(t, result.lowerBoundBPS)

	result = probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse("/early"), 64*1024, tlsConfig)
	require.False(t, result.valid)
	require.Equal(t, "early-eof", result.reason)
	require.Equal(t, int64(16*1024), result.bytes)

	result = probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse("/zero"), 64*1024, tlsConfig)
	require.Equal(t, "zero-bytes", result.reason)
	result = probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse("/status"), 64*1024, tlsConfig)
	require.Equal(t, "non-2xx", result.reason)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result = probeVaneCapabilityWithTLSConfig(ctx, proxy, parse("/slow"), 64*1024, tlsConfig)
	require.False(t, result.valid)
	require.Contains(t, []string{"read-timeout", "canceled"}, result.reason)
	require.Equal(t, int32(5), proxy.dials.Load(), "each probe must dial the selected challenger directly")
}

// PROBE-BOUND-001: the measurement floor keeps a tiny body-read window from
// inflating a proven lower bound; clamping errs low by design.
func TestVaneProbeBoundDuration(t *testing.T) {
	require.Equal(t, vaneRacingProbeMinDuration, vaneProbeBoundDuration(0))
	require.Equal(t, vaneRacingProbeMinDuration, vaneProbeBoundDuration(time.Nanosecond))
	require.Equal(t, vaneRacingProbeMinDuration, vaneProbeBoundDuration(vaneRacingProbeMinDuration-time.Nanosecond))
	require.Equal(t, vaneRacingProbeMinDuration, vaneProbeBoundDuration(vaneRacingProbeMinDuration))
	require.Equal(t, 150*time.Millisecond, vaneProbeBoundDuration(150*time.Millisecond))
}

// PROBE-BOUND-001: when the header consumes most of the probe budget the
// body-read window shrinks to milliseconds, and without the 100ms measurement
// floor a 4KB body would report an inflated ~32Mbps bound. That bound feeds
// race verdicts, the capability cache and requiredBPS comparisons, so it must
// stay conservative (≤1Mbps for 4KB) in both lower-bound branches.
func TestVaneRacingProbeHeaderSlowBodyFastLowerBound(t *testing.T) {
	payload := make([]byte, 16*1024)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/slow-header-cap":
			// Header eats most of the 4s budget, then the body lands instantly:
			// the measured body window is milliseconds, and the exact byteLimit
			// makes the probe end in the cap-hit branch.
			time.Sleep(3500 * time.Millisecond)
			writer.Header().Set("Content-Length", fmt.Sprint(4096))
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(payload[:4096])
		case "/slow-header-stall":
			// Same shape, but the probe ends in the read-timeout branch: 4KB
			// arrive just before the deadline, then the body stalls.
			time.Sleep(3900 * time.Millisecond)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(payload[:4096])
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: pool}
	proxy := newVaneNetworkTestProxy("probe-bound")
	parse := func(path string) *url.URL {
		endpoint, err := url.Parse(server.URL + path)
		require.NoError(t, err)
		return endpoint
	}

	type probeOutcome struct {
		path   string
		result vaneProbeResult
	}
	outcomes := make(chan probeOutcome, 2)
	run := func(path string, byteLimit int64) {
		outcomes <- probeOutcome{path, probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse(path), byteLimit, tlsConfig)}
	}
	go run("/slow-header-cap", 4096)
	go run("/slow-header-stall", 4<<20)
	results := make(map[string]vaneProbeResult, 2)
	for i := 0; i < 2; i++ {
		outcome := <-outcomes
		results[outcome.path] = outcome.result
	}
	require.Equal(t, int32(2), proxy.dials.Load(), "each probe must dial the selected challenger directly")

	capResult := results["/slow-header-cap"]
	require.True(t, capResult.valid)
	require.True(t, capResult.capHit)
	require.Equal(t, int64(4096), capResult.bytes)
	require.GreaterOrEqual(t, capResult.duration, vaneRacingProbeMinDuration, "the measurement floor must hold the duration")
	require.LessOrEqual(t, capResult.lowerBoundBPS, 1_000_000.0,
		"4KB over a millisecond body window must clamp to ~0.33Mbps, not inflate to 32Mbps")
	require.InDelta(t, 8*float64(capResult.bytes)/capResult.duration.Seconds(), capResult.lowerBoundBPS, 1,
		"the lower bound must use the cap-hit formula on the clamped duration")

	timeoutResult := results["/slow-header-stall"]
	require.True(t, timeoutResult.valid, "bytes read before the deadline still measure the node")
	require.Equal(t, "read-timeout", timeoutResult.reason)
	require.Equal(t, int64(4096), timeoutResult.bytes)
	require.GreaterOrEqual(t, timeoutResult.duration, vaneRacingProbeMinDuration, "the measurement floor must hold the duration")
	require.LessOrEqual(t, timeoutResult.lowerBoundBPS, 1_000_000.0,
		"4KB over a near-expired budget must clamp instead of inflating the bound")
	require.InDelta(t, 8*float64(timeoutResult.bytes)/timeoutResult.duration.Seconds(), timeoutResult.lowerBoundBPS, 1,
		"the lower bound must use the read-timeout formula on the clamped duration")
}

// PROBE-PARTIAL-001: bytes already read when the probe deadline fires are a
// proven lower bound, while zero bytes, early-eof and read-error stay invalid.
func TestVaneRacingProbePartialReadIsLowerBound(t *testing.T) {
	payload := make([]byte, 128*1024)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/stall-after-bytes":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(payload[:64*1024])
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		case "/stall-before-bytes":
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
		case "/short-flush":
			// Content-Length promises more than is written, then the handler
			// returns: the client sees a read error, not a clean EOF.
			writer.Header().Set("Content-Length", fmt.Sprint(1<<20))
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(payload[:32*1024])
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	proxy := newVaneNetworkTestProxy("probe-partial")
	parse := func(path string) *url.URL {
		endpoint, err := url.Parse(server.URL + path)
		require.NoError(t, err)
		return endpoint
	}

	partialCtx, partialCancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer partialCancel()
	result := probeVaneCapabilityWithTLSConfig(partialCtx, proxy, parse("/stall-after-bytes"), 4<<20, &tls.Config{RootCAs: pool})
	require.True(t, result.valid, "a deadline after bytes arrived must still measure the node")
	require.Equal(t, "read-timeout", result.reason)
	require.False(t, result.capHit)
	require.Equal(t, int64(64*1024), result.bytes)
	require.Positive(t, result.lowerBoundBPS)
	require.InDelta(t, 8*float64(result.bytes)/result.duration.Seconds(), result.lowerBoundBPS, 1,
		"the lower bound must use the cap-hit formula on the bytes actually read")

	zeroCtx, zeroCancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer zeroCancel()
	result = probeVaneCapabilityWithTLSConfig(zeroCtx, proxy, parse("/stall-before-bytes"), 4<<20, &tls.Config{RootCAs: pool})
	require.False(t, result.valid, "no bytes means nothing was measured")
	require.Equal(t, "read-timeout", result.reason)
	require.Zero(t, result.bytes)

	result = probeVaneCapabilityWithTLSConfig(t.Context(), proxy, parse("/short-flush"), 4<<20, &tls.Config{RootCAs: pool})
	require.False(t, result.valid, "a broken connection stays invalid even with bytes")
	require.Equal(t, "read-error", result.reason)
	require.Equal(t, int64(32*1024), result.bytes)
}

// PROBE-PARTIAL-001 + RACE-ENGINE-001: a partial (read-timeout) measurement is
// a real lower bound, so it can win when it clears the demand, and it still
// loses when it does not.
func TestVaneRacingPartialLowerBoundGatesOnDemand(t *testing.T) {
	t.Run("partial bound above demand wins", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		gamma := newVaneTestProxy("gamma", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
			if proxy.Name() == "beta" {
				return vaneProbeResult{valid: true, reason: "read-timeout", bytes: 256 * 1024, duration: 500 * time.Millisecond, lowerBoundBPS: 4_000_000}
			}
			return vaneProbeResult{reason: "read-timeout", bytes: 0, duration: time.Second}
		}
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr-partial.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		resultCh := make(chan vaneRaceResult, 1)
		scheduled, reason := group.scheduleMediaRace(request, func(result vaneRaceResult) { resultCh <- result })
		require.True(t, scheduled, reason)
		result := <-resultCh
		require.Equal(t, "beta", result.winner.name, "a partial bound above requiredBPS must win")
	})

	t.Run("partial bound below demand loses", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			return vaneProbeResult{valid: true, reason: "read-timeout", bytes: 64 * 1024, duration: 400 * time.Millisecond, lowerBoundBPS: 1_500_000}
		}
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr-partial-low.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) {
			t.Error("a bound below requiredBPS must not produce a winner")
		})
		require.True(t, scheduled, reason)
		waitVaneRaceIdle(t, group)
		require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)
	})
}

func newVaneRaceRequestForTest(t *testing.T, group *Vane, metadata *C.Metadata) vaneRaceRequest {
	t.Helper()
	// COLD-PICK: suppress the cold-pick probe so the pick does not consume
	// budget or write capability evidence; race tests measure the race probe.
	group.mu.Lock()
	group.lastPickProbeAt[group.mediaTargetKey(metadata.Host, metadata.DstPort).target] = group.clock.Now()
	group.mu.Unlock()
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	key, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	return vaneRaceRequest{
		targetKey: key,
		mediaKey:  group.mediaTargetKey(metadata.Host, metadata.DstPort),
		target:    metadata.Host,
		port:      metadata.DstPort,
		current: vaneMemberLease{
			name: decision.proxy.Name(), identity: decision.identity, epoch: decision.nodeEpoch,
		},
		currentBPS:  1_000_000,
		requiredBPS: 2_000_000,
		totalBytes:  4 * 1024 * 1024,
		age:         20 * time.Second,
		lowWindows:  3,
		generation:  group.learningGeneration,
		requestedAt: group.clock.Now(),
	}
}

// RACE-ENGINE-001: the first qualified challenger wins and its peers are canceled.
func TestVaneRacingEngineFirstQualifiedWinsAndCancelsPeer(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	gamma := newVaneTestProxy("gamma", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)

	betaCanceled := make(chan struct{})
	group.racing.probe = func(ctx context.Context, proxy C.Proxy, _ *url.URL, limit int64) vaneProbeResult {
		if proxy.Name() == "beta" {
			<-ctx.Done()
			close(betaCanceled)
			return vaneProbeResult{reason: "canceled", bytes: 1024}
		}
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: limit, duration: time.Second, lowerBoundBPS: 8 * float64(limit), capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	resultCh := make(chan vaneRaceResult, 1)
	scheduled, reason := group.scheduleMediaRace(request, func(result vaneRaceResult) { resultCh <- result })
	require.True(t, scheduled, reason)
	result := <-resultCh
	require.Equal(t, "gamma", result.winner.name)
	select {
	case <-betaCanceled:
	case <-time.After(time.Second):
		t.Fatal("losing probe was not canceled")
	}
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight && len(group.racingRuntime.activeTasks) == 0
	}, time.Second, time.Millisecond)
}

// RACE-IDENTITY-001: a same-name replacement must not inherit probe results.
func TestVaneRacingIdentityRejectsSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta-old"
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	started := make(chan struct{})
	release := make(chan struct{})
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		close(started)
		<-release
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	called := atomic.Bool{}
	scheduled, _ := group.scheduleMediaRace(request, func(vaneRaceResult) { called.Store(true) })
	require.True(t, scheduled)
	<-started
	newBeta := newVaneTestProxy("beta", true, true)
	newBeta.identity = "beta-new"
	provider.setProxies(alpha, newBeta)
	group.refreshNodeIdentities(provider.Proxies())
	close(release)
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight
	}, time.Second, time.Millisecond)
	require.False(t, called.Load())
	group.racingRuntime.mu.Lock()
	_, oldCached := group.racingRuntime.capabilities[vaneMemberLease{name: "beta", identity: "beta-old"}]
	_, newCached := group.racingRuntime.capabilities[vaneMemberLease{name: "beta", identity: "beta-new"}]
	group.racingRuntime.mu.Unlock()
	require.False(t, oldCached)
	require.False(t, newCached)
}

// RACE-BUDGET-001 + RACE-LIFECYCLE-001: hard byte reservation and close-time cancellation.
func TestVaneRacingBudgetAndLifecycle(t *testing.T) {
	t.Run("hard byte reservation", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		gamma := newVaneTestProxy("gamma", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		group.racing.budgetBytesHour = vaneRacingProbeByteCap
		var calls atomic.Int32
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			calls.Add(1)
			return vaneProbeResult{valid: false, reason: "early-eof", bytes: vaneRacingProbeByteCap / 2, duration: time.Second}
		}
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		scheduled, _ := group.scheduleMediaRace(request, func(vaneRaceResult) {})
		require.True(t, scheduled)
		require.Eventually(t, func() bool {
			group.racingRuntime.mu.Lock()
			defer group.racingRuntime.mu.Unlock()
			return !group.racingRuntime.inFlight
		}, time.Second, time.Millisecond)
		require.Equal(t, int32(1), calls.Load())
		group.racingRuntime.mu.Lock()
		require.LessOrEqual(t, group.racingRuntime.budget.used+group.racingRuntime.budget.reserved, group.racing.budgetBytesHour)
		group.racingRuntime.mu.Unlock()
	})

	t.Run("close cancels in flight", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		started := make(chan struct{})
		var once sync.Once
		group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
			once.Do(func() { close(started) })
			<-ctx.Done()
			return vaneProbeResult{reason: "canceled"}
		}
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		called := atomic.Bool{}
		scheduled, _ := group.scheduleMediaRace(request, func(vaneRaceResult) { called.Store(true) })
		require.True(t, scheduled)
		<-started
		require.NoError(t, group.Close())
		require.Eventually(t, func() bool {
			group.racingRuntime.mu.Lock()
			defer group.racingRuntime.mu.Unlock()
			return !group.racingRuntime.inFlight && len(group.racingRuntime.activeTasks) == 0
		}, time.Second, time.Millisecond)
		require.False(t, called.Load())
	})
}

// RACE-MODE-001: shadow never changes baseline selection or policy state.
func TestVaneRacingModeTruthTable(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			clock := newVaneConnTestClock()
			alpha := newVaneTestProxy("alpha", true, true)
			beta := newVaneTestProxy("beta", true, true)
			beta.delay = 10
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
			configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
			configureVaneRacingForTest(t, group, mode)
			// CHAIN-01: the shadow baseline close needs challenger evidence. The
			// helper's demand=1/low=3M with a 1 Mbps sample makes any evidence
			// >= 3M knownGood, and a knownGood plan never races, so the
			// would-handoff counter (fed by the race callback) needs the
			// no-challenger path instead: leave beta without evidence, let the
			// shadow dispatch schedule the race, and let the probe fill the
			// capability cache. The baseline close itself is vetoed by the
			// evidence gate (no-evidence-candidate), which is the CHAIN-01
			// contract; wouldHandoff comes from the race callback with the
			// probe's 100M bound.
			group.ensureNodeLocked(beta.Name(), clock.Now())
			group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
				return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
			}
			metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
			suppressColdPickProbeForTest(t, group, metadata)
			decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
			flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
			flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
			actions := make(chan vanePolicyAction, 1)
			flow.setPolicySubmitter(func(action vanePolicyAction, _ bool) { actions <- action })
			sample := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true}
			require.Nil(t, flow.observe(sample))
			require.Nil(t, flow.observe(sample))
			baselineAction := flow.observe(sample)

			if mode == vaneRacingShadow {
				// CHAIN-01: without challenger evidence the baseline close is
				// vetoed (no-evidence-candidate) and the flow is not closed;
				// the race still runs and records would-handoff.
				require.Nil(t, baselineAction)
				require.Eventually(t, func() bool { return group.VaneDiagnostics().Counters.WouldHandoff > 0 }, time.Second, time.Millisecond)
				suppressions := group.VaneDiagnostics().Suppressions
				require.Greater(t, suppressions["no-evidence-candidate"], uint64(0))
				group.mu.Lock()
				require.Empty(t, group.mediaHints)
				require.Empty(t, group.targetHandoffs)
				require.Empty(t, group.targetPreferences)
				group.mu.Unlock()
				// SHADOW-02: the race callback only records would-handoff; it
				// must never reach submitPolicyAction.
				select {
				case <-actions:
					t.Fatal("shadow race must not submit a policy action")
				default:
				}
			} else {
				require.Nil(t, baselineAction)
				var action vanePolicyAction
				select {
				case action = <-actions:
				case <-time.After(time.Second):
					t.Fatal("racing on did not submit a handoff action")
				}
				require.True(t, action())
				group.mu.Lock()
				require.Empty(t, group.mediaHints)
				require.Len(t, group.targetHandoffs, 1)
				group.mu.Unlock()
			}
		})
	}
}

// RACE-PROBE-001 + RACE-BUDGET-001: canceled probes still charge the bytes they read.
func TestVaneRacingProbeCancellationChargesReadBytes(t *testing.T) {
	// Budget settlement is intentionally based on returned actual bytes even
	// when the probe is canceled or invalid.
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true))
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "canceled", bytes: 12345, duration: time.Millisecond}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, _ := group.scheduleMediaRace(request, func(vaneRaceResult) { t.Fatal("unexpected winner") })
	require.True(t, scheduled)
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight
	}, time.Second, time.Millisecond)
	group.racingRuntime.mu.Lock()
	used := group.racingRuntime.budget.used
	group.racingRuntime.mu.Unlock()
	require.Equal(t, int64(12345), used)
}

// RACE-ENGINE-001: a race without a qualified winner must not mutate selection state.
func TestVaneRacingNoWinnerDoesNotCommitPolicyState(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true))
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 1, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, _ := group.scheduleMediaRace(request, func(vaneRaceResult) { t.Fatal("unexpected winner") })
	require.True(t, scheduled)
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight
	}, time.Second, time.Millisecond)
	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.targetPreferences)
	require.Empty(t, group.mediaSlowCooldowns)
	require.Empty(t, group.mediaBudgets)
	group.mu.Unlock()
	require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)
}

var _ C.Proxy = (*vaneNetworkTestProxy)(nil)
var _ = errors.Is

// TARGET-BOUND-001: the capability cache is bounded and stale entries are pruned.
func TestVaneRacingCapabilityPrune(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)

	t.Run("ttl expiry removes stale capability", func(t *testing.T) {
		lease := vaneMemberLease{name: "stale", identity: "stale-id", epoch: 1}
		group.racingRuntime.mu.Lock()
		group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{
			member: lease, lowerBoundBPS: 1000, bytes: 1000,
			observedAt: clock.Now().Add(-vaneRacingCapabilityTTL - time.Minute),
		}
		group.pruneCapabilitiesLocked(clock.Now())
		_, ok := group.racingRuntime.capabilities[lease]
		group.racingRuntime.mu.Unlock()
		require.False(t, ok, "stale capability must be pruned")
	})

	t.Run("fresh capability retained", func(t *testing.T) {
		lease := vaneMemberLease{name: "fresh", identity: "fresh-id", epoch: 1}
		group.racingRuntime.mu.Lock()
		group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{
			member: lease, lowerBoundBPS: 1000, bytes: 1000, observedAt: clock.Now(),
		}
		group.pruneCapabilitiesLocked(clock.Now())
		_, ok := group.racingRuntime.capabilities[lease]
		group.racingRuntime.mu.Unlock()
		require.True(t, ok, "fresh capability must survive pruning")
	})

	t.Run("zero observedAt removed", func(t *testing.T) {
		lease := vaneMemberLease{name: "zero", identity: "zero-id", epoch: 1}
		group.racingRuntime.mu.Lock()
		group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{member: lease}
		group.pruneCapabilitiesLocked(clock.Now())
		_, ok := group.racingRuntime.capabilities[lease]
		group.racingRuntime.mu.Unlock()
		require.False(t, ok, "zero-time record must be pruned")
	})

	t.Run("lru eviction over state limit", func(t *testing.T) {
		group.racingRuntime.mu.Lock()
		base := clock.Now()
		for i := 0; i < vaneTargetStateLimit+8; i++ {
			lease := vaneMemberLease{name: fmt.Sprintf("n%d", i), identity: fmt.Sprintf("i%d", i), epoch: uint64(i)}
			// 全部新鲜（TTL 内），仅 observedAt 错开——触发 LRU 而非 TTL 分支
			group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{
				member: lease, lowerBoundBPS: float64(i), bytes: 1, observedAt: base.Add(-time.Duration(i) * time.Millisecond),
			}
		}
		before := len(group.racingRuntime.capabilities)
		group.pruneCapabilitiesLocked(clock.Now())
		after := len(group.racingRuntime.capabilities)
		// observedAt 随 i 递减：最旧 = i 最大（n1031..n1024），最新 = i=0
		oldest := vaneMemberLease{name: fmt.Sprintf("n%d", vaneTargetStateLimit+7), identity: fmt.Sprintf("i%d", vaneTargetStateLimit+7), epoch: uint64(vaneTargetStateLimit + 7)}
		_, oldestKept := group.racingRuntime.capabilities[oldest]
		newest := vaneMemberLease{name: "n0", identity: "i0", epoch: 0}
		_, newestKept := group.racingRuntime.capabilities[newest]
		group.racingRuntime.mu.Unlock()
		require.Less(t, after, before, "over-limit state must shrink")
		require.Equal(t, vaneTargetStateLimit, after, "state must be trimmed to the limit")
		require.False(t, oldestKept, "oldest capability must be evicted")
		require.True(t, newestKept, "newest capability must be retained")
	})
}

// RACE-BUDGET-001: settle refunds the reserved-but-unused difference.
func TestVaneRacingBudgetSettle(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	group.racing.budgetBytesHour = vaneRacingProbeByteCap * 4

	t.Run("normal settle", func(t *testing.T) {
		group.racingRuntime.mu.Lock()
		group.racingRuntime.budget.reserved = 1000
		group.racingRuntime.budget.used = 0
		group.racingRuntime.mu.Unlock()
		group.settleRaceBudget(1000, 600)
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		require.Equal(t, int64(0), group.racingRuntime.budget.reserved)
		require.Equal(t, int64(600), group.racingRuntime.budget.used)
	})

	t.Run("negative actual clamps to zero", func(t *testing.T) {
		group.racingRuntime.mu.Lock()
		group.racingRuntime.budget.reserved = 500
		group.racingRuntime.budget.used = 100
		group.racingRuntime.mu.Unlock()
		group.settleRaceBudget(500, -50)
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		require.Equal(t, int64(0), group.racingRuntime.budget.reserved)
		require.Equal(t, int64(100), group.racingRuntime.budget.used, "negative actual must not reduce used")
	})

	t.Run("actual above reserved clamps to reserved", func(t *testing.T) {
		group.racingRuntime.mu.Lock()
		group.racingRuntime.budget.reserved = 400
		group.racingRuntime.budget.used = 0
		group.racingRuntime.mu.Unlock()
		group.settleRaceBudget(400, 900)
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		require.Equal(t, int64(0), group.racingRuntime.budget.reserved)
		require.Equal(t, int64(400), group.racingRuntime.budget.used, "actual must clamp to reserved cap")
	})

	t.Run("reserved underflow floors at zero", func(t *testing.T) {
		group.racingRuntime.mu.Lock()
		group.racingRuntime.budget.reserved = 100
		group.racingRuntime.budget.used = 0
		group.racingRuntime.mu.Unlock()
		group.settleRaceBudget(500, 500)
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		require.Equal(t, int64(0), group.racingRuntime.budget.reserved)
		// 实现语义：used += min(actual, 本次预留请求)——保持 used+outstanding ≤ 预算不变量
		require.Equal(t, int64(500), group.racingRuntime.budget.used)
	})
}

// RACE-LIFECYCLE-001: schedule guards keep exactly one race in flight per group.
func TestVaneRacingScheduleGuards(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	metadata := &C.Metadata{Host: "rr.guard.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	for _, invalid := range []string{"nil-callback", "empty-scope"} {
		t.Run(invalid, func(t *testing.T) {
			request := newVaneRaceRequestForTest(t, group, metadata)
			callback := func(vaneRaceResult) {}
			if invalid == "nil-callback" {
				callback = nil
			} else {
				request.targetKey.targetScope = ""
			}
			scheduled, reason := group.scheduleMediaRace(request, callback)
			require.False(t, scheduled)
			require.Equal(t, "invalid-race-request", reason)
		})
	}

	t.Run("closed group rejects", func(t *testing.T) {
		configureVaneRacingForTest(t, group, vaneRacingShadow)
		group.racingRuntime.mu.Lock()
		group.racingRuntime.closed = true
		group.racingRuntime.mu.Unlock()
		request := newVaneRaceRequestForTest(t, group, metadata)
		scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) {})
		require.False(t, scheduled)
		require.Equal(t, "group-closed", reason)
		group.racingRuntime.mu.Lock()
		group.racingRuntime.closed = false
		group.racingRuntime.mu.Unlock()
	})

	t.Run("in-flight rejects second race", func(t *testing.T) {
		configureVaneRacingForTest(t, group, vaneRacingShadow)
		group.racingRuntime.mu.Lock()
		group.racingRuntime.inFlight = true
		group.racingRuntime.mu.Unlock()
		request := newVaneRaceRequestForTest(t, group, metadata)
		scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) {})
		require.False(t, scheduled)
		require.Equal(t, "race-in-flight", reason)
		group.racingRuntime.mu.Lock()
		group.racingRuntime.inFlight = false
		group.racingRuntime.mu.Unlock()
	})

	t.Run("no-winner suppression window rejects", func(t *testing.T) {
		configureVaneRacingForTest(t, group, vaneRacingShadow)
		key := vaneTargetKey{transport: vaneTransportTCP, targetScope: "googlevideo.com", port: 443}
		group.racingRuntime.mu.Lock()
		group.racingRuntime.noWinnerUntil[key] = clock.Now().Add(time.Minute)
		group.racingRuntime.mu.Unlock()
		request := newVaneRaceRequestForTest(t, group, metadata)
		scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) {})
		require.False(t, scheduled)
		require.Contains(t, reason, "no-winner")
		group.racingRuntime.mu.Lock()
		delete(group.racingRuntime.noWinnerUntil, key)
		group.racingRuntime.mu.Unlock()
	})
}
