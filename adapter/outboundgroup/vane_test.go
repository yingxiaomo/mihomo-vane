package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type vaneTestProxy struct {
	*outbound.Base
	identity   string
	alive      bool
	delay      uint16
	dialErr    error
	packetErr  error
	dialConn   C.Conn
	packetConn C.PacketConn
	dialHook   func()
	packetHook func()
	aliveHook  func()
}

func newVaneTestProxy(name string, alive, udp bool) *vaneTestProxy {
	return &vaneTestProxy{
		Base:     outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Compatible, UDP: udp}),
		identity: "test:" + name,
		alive:    alive,
		delay:    1,
	}
}

func (p *vaneTestProxy) PersistentIdentity() string { return p.identity }

func (p *vaneTestProxy) Adapter() C.ProxyAdapter { return p }
func (p *vaneTestProxy) AliveForTestUrl(string) bool {
	if p.aliveHook != nil {
		p.aliveHook()
	}
	return p.alive
}
func (p *vaneTestProxy) DelayHistory() []C.DelayHistory { return nil }
func (p *vaneTestProxy) ExtraDelayHistories() map[string]C.ProxyState {
	return nil
}
func (p *vaneTestProxy) LastDelayForTestUrl(string) uint16 { return p.delay }
func (p *vaneTestProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	return 1, nil
}
func (p *vaneTestProxy) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	if p.dialHook != nil {
		p.dialHook()
	}
	return p.dialConn, p.dialErr
}
func (p *vaneTestProxy) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	if p.packetHook != nil {
		p.packetHook()
	}
	return p.packetConn, p.packetErr
}

type vaneEarlyTestConn struct {
	*vaneConnTestConn
}

func (*vaneEarlyTestConn) NeedHandshake() bool { return true }

type vaneTestProvider struct {
	mu            sync.Mutex
	name          string
	healthURL     string
	proxies       []C.Proxy
	version       uint32
	touches       int
	snapshotCalls int
	registered    []vaneTestHealthRegistration
}

type vaneTestHealthRegistration struct {
	url      string
	filter   string
	interval uint
}

func newVaneTestProvider(proxies ...C.Proxy) *vaneTestProvider {
	return &vaneTestProvider{name: "vane-test-provider", healthURL: C.DefaultTestURL, proxies: proxies, version: 1}
}

func (p *vaneTestProvider) Name() string               { return p.name }
func (p *vaneTestProvider) VehicleType() P.VehicleType { return P.Inline }
func (p *vaneTestProvider) Type() P.ProviderType       { return P.Proxy }
func (p *vaneTestProvider) Initial() error             { return nil }
func (p *vaneTestProvider) Update() error              { return nil }
func (p *vaneTestProvider) HealthCheck()               {}
func (p *vaneTestProvider) HealthCheckURL() string     { return p.healthURL }
func (p *vaneTestProvider) RegisterHealthCheckTask(url string, _ utils.IntRanges[uint16], filter string, interval uint) {
	p.mu.Lock()
	p.registered = append(p.registered, vaneTestHealthRegistration{url: url, filter: filter, interval: interval})
	p.mu.Unlock()
}
func (p *vaneTestProvider) Proxies() []C.Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]C.Proxy(nil), p.proxies...)
}
func (p *vaneTestProvider) ProxiesWithLock() ([]C.Proxy, func()) {
	p.mu.Lock()
	p.snapshotCalls++
	return p.proxies, p.mu.Unlock
}
func (p *vaneTestProvider) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.proxies)
}
func (p *vaneTestProvider) Touch() {
	p.mu.Lock()
	p.touches++
	p.mu.Unlock()
}
func (p *vaneTestProvider) Version() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}
func (p *vaneTestProvider) setProxies(proxies ...C.Proxy) {
	p.mu.Lock()
	p.proxies = append([]C.Proxy(nil), proxies...)
	p.version++
	p.mu.Unlock()
}

func newVaneGroupForTest(clock vaneClock, maxStates int, stateTTL time.Duration, proxies ...C.Proxy) (*Vane, *vaneTestProvider) {
	provider := newVaneTestProvider(proxies...)
	fallback := newVaneTestProxy("fallback", true, false)
	group := newVaneWithClock(
		GroupCommonOption{Name: "vane-test", URL: C.DefaultTestURL},
		fallback,
		[]P.ProxyProvider{provider},
		nil,
		vaneDefaultSwitchMargin,
		vaneDefaultCooldown,
		stateTTL,
		maxStates,
		clock,
	)
	installVaneEventRecorder(group)
	return group, provider
}

func TestNewVaneOptions(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)

	t.Run("defaults", func(t *testing.T) {
		group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{}, fallback, nil)
		require.NoError(t, err)
		require.Equal(t, int64(50_000), group.switchMargin)
		require.Equal(t, vaneDefaultCooldown, group.targetCooldown)
		require.Equal(t, vaneDefaultStateTTL, group.stateTTL)
		require.Equal(t, vaneDefaultMaxStates, group.maxStates)
		require.False(t, group.exploration.enabled)
		require.Zero(t, group.exploration.interval)
		require.False(t, group.gray.isEnabled())
	})

	t.Run("exploration uses an explicit safe opt-in and default interval", func(t *testing.T) {
		group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{Exploration: true}, fallback, nil)
		require.NoError(t, err)
		require.True(t, group.exploration.enabled)
		require.Equal(t, uint64(vaneDefaultExplorationInterval), group.exploration.interval)
	})

	t.Run("valid boundaries", func(t *testing.T) {
		group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{
			SwitchMargin:        1,
			TargetCooldown:      vaneMaximumConfigSeconds,
			StateTTL:            vaneMaximumConfigSeconds,
			MaxStates:           1,
			Exploration:         true,
			ExplorationInterval: vaneMaximumExplorationInterval,
		}, fallback, nil)
		require.NoError(t, err)
		require.Equal(t, int64(1_000_000), group.switchMargin)
		require.Equal(t, time.Duration(vaneMaximumConfigSeconds)*time.Second, group.targetCooldown)
		require.Equal(t, time.Duration(vaneMaximumConfigSeconds)*time.Second, group.stateTTL)
		require.Equal(t, 1, group.maxStates)
		require.Equal(t, uint64(vaneMaximumExplorationInterval), group.exploration.interval)
	})

	tests := []struct {
		name   string
		option VaneOption
	}{
		{"negative switch margin", VaneOption{SwitchMargin: -0.01}},
		{"switch margin above one", VaneOption{SwitchMargin: 1.01}},
		{"negative target cooldown", VaneOption{TargetCooldown: -1}},
		{"target cooldown too large", VaneOption{TargetCooldown: vaneMaximumConfigSeconds + 1}},
		{"negative state ttl", VaneOption{StateTTL: -1}},
		{"state ttl too large", VaneOption{StateTTL: vaneMaximumConfigSeconds + 1}},
		{"negative max states", VaneOption{MaxStates: -1}},
		{"interval while exploration disabled", VaneOption{ExplorationInterval: 2}},
		{"exploration interval one", VaneOption{Exploration: true, ExplorationInterval: 1}},
		{"negative exploration interval", VaneOption{Exploration: true, ExplorationInterval: -1}},
		{"exploration interval too large", VaneOption{Exploration: true, ExplorationInterval: vaneMaximumExplorationInterval + 1}},
		{"invalid scene rule", VaneOption{SceneRules: []string{"NETWORK,icmp,media"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewVane(GroupCommonOption{Name: "vane"}, test.option, fallback, nil)
			require.Error(t, err)
		})
	}

	_, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{}, nil, nil)
	require.EqualError(t, err, "empty fallback proxy not exist")
}

func TestVaneMediaRemovedKeysRejected(t *testing.T) {
	keys := []string{
		"media-low-throughput", "media-low-windows", "media-min-age", "media-min-bytes",
		"media-buffer-guard", "media-reconnect-cooldown", "media-slow-cooldown", "media-hint-ttl",
		"media-challenger-ratio", "media-reconnect-budget", "media-budget-window",
		"media-max-low-windows", "racing-budget-mb-hour",
	}
	proxyMap := map[string]C.Proxy{
		"COMPATIBLE": newVaneTestProxy("COMPATIBLE", true, false),
		"alpha":      newVaneTestProxy("alpha", true, true),
	}
	config := map[string]any{"name": "vane", "type": "vane", "proxies": []string{"alpha"}, "media-demand-bps": 5_000_000}
	providers := map[string]P.ProxyProvider{}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			config[key] = 0
			defer delete(config, key)
			_, err := ParseProxyGroup(config, proxyMap, providers, nil, nil)
			require.ErrorContains(t, err, key)
			require.ErrorContains(t, err, "now hardcoded in the kernel")
			require.Empty(t, providers)
		})
	}
	config["MEDIA-LOW-THROUGHPUT"] = nil
	config["media-buffer-guard"] = 3
	config["media-max-low-windows"] = 0
	_, err := ParseProxyGroup(config, proxyMap, providers, nil, nil)
	require.EqualError(t, err, "vane media thresholds media-low-throughput, media-buffer-guard, media-max-low-windows are now hardcoded in the kernel; remove them from the config")
	delete(config, "MEDIA-LOW-THROUGHPUT")
	delete(config, "media-buffer-guard")
	delete(config, "media-max-low-windows")
	parsed, err := ParseProxyGroup(config, proxyMap, providers, nil, nil)
	require.NoError(t, err)
	group := parsed.(*Vane)
	t.Cleanup(func() { _ = group.Close() })
	require.Equal(t, 4, group.media.maxLowWindows)
	require.Equal(t, float64(5_000_000), group.media.demandBPS)
}

// DEMAND-01..04: media-demand-bps accepts a decimal-suffixed string ("10M")
// and a plain byte count interchangeably; "10M" is exactly 10000000, so the
// string form never shifts the demand.
func TestVaneMediaDemandBandwidthParsing(t *testing.T) {
	proxyMap := map[string]C.Proxy{
		"COMPATIBLE": newVaneTestProxy("COMPATIBLE", true, false),
		"alpha":      newVaneTestProxy("alpha", true, true),
	}
	parseDemand := func(t *testing.T, value any) (float64, error) {
		t.Helper()
		config := map[string]any{"name": "vane", "type": "vane", "proxies": []string{"alpha"}, "media-demand-bps": value}
		parsed, err := ParseProxyGroup(config, proxyMap, map[string]P.ProxyProvider{}, nil, nil)
		if err != nil {
			return 0, err
		}
		group := parsed.(*Vane)
		t.Cleanup(func() { _ = group.Close() })
		return group.media.demandBPS, nil
	}

	t.Run("DEMAND-01 decimal suffixes", func(t *testing.T) {
		for _, tc := range []struct {
			text string
			want float64
		}{{"10M", 10_000_000}, {"5M", 5_000_000}, {"1.5M", 1_500_000}, {"500K", 500_000}} {
			got, err := parseDemand(t, tc.text)
			require.NoError(t, err, tc.text)
			require.Equal(t, tc.want, got, tc.text)
		}
	})

	t.Run("DEMAND-02 plain bytes stay compatible", func(t *testing.T) {
		got, err := parseDemand(t, 10_000_000)
		require.NoError(t, err)
		require.Equal(t, float64(10_000_000), got)
	})

	t.Run("DEMAND-03 invalid values fail with clear errors", func(t *testing.T) {
		_, err := parseDemand(t, "abc")
		require.ErrorContains(t, err, "bandwidth")
		_, err = parseDemand(t, "10X")
		require.ErrorContains(t, err, "bandwidth")
		_, err = parseDemand(t, int64(vaneMaximumMediaThroughputBPS)+1)
		require.ErrorContains(t, err, "media-demand-bps must be between 0 and")
		_, err = parseDemand(t, "2G")
		require.ErrorContains(t, err, "media-demand-bps must be between 0 and")
	})

	t.Run("DEMAND-04 string and integer forms agree", func(t *testing.T) {
		fromString, err := parseDemand(t, "10M")
		require.NoError(t, err)
		fromInt, err := parseDemand(t, 10_000_000)
		require.NoError(t, err)
		require.Equal(t, fromInt, fromString, `"10M" must be exactly 10000000`)
	})
}

func TestParseVaneProxyGroup(t *testing.T) {
	newInputs := func() (map[string]C.Proxy, map[string]P.ProxyProvider) {
		return map[string]C.Proxy{
			"COMPATIBLE": A.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "COMPATIBLE", Type: C.Compatible})),
			"fallback":   newVaneTestProxy("fallback", true, false),
			"alpha":      newVaneTestProxy("alpha", true, true),
			"beta":       newVaneTestProxy("beta", true, true),
		}, map[string]P.ProxyProvider{}
	}

	t.Run("proxies scene rules and empty fallback are wired", func(t *testing.T) {
		proxyMap, providerMap := newInputs()
		parsed, err := ParseProxyGroup(map[string]any{
			"name":                     "vane-group",
			"type":                     "vane",
			"proxies":                  []string{"beta", "alpha"},
			"scene-rules":              []string{"DOMAIN-SUFFIX,video.example,media"},
			"empty-fallback":           "fallback",
			"switch-margin":            0.2,
			"target-cooldown":          9,
			"state-ttl":                60,
			"max-states":               7,
			"exploration":              true,
			"exploration-interval":     17,
			"gray-failure-observation": true,
			"media-reconnect":          true,
			"media-reconnect-domains":  []string{"video.example"},
			"media-demand-bps":         2_000_000,
			"disable-udp":              false,
			"expected-status":          "204",
			"include-all":              false,
			"include-all-proxies":      false,
		}, proxyMap, providerMap, nil, nil)
		require.NoError(t, err)

		group, ok := parsed.(*Vane)
		require.True(t, ok)
		require.Equal(t, C.Vane, group.Type())
		require.Equal(t, C.DefaultTestURL, group.testURL)
		require.Equal(t, "fallback", group.EmptyFallback().Name())
		require.Equal(t, []string{"beta", "alpha"}, proxyNames(group.Proxies()))
		require.Equal(t, vaneSceneMedia, classifyVaneScene(&C.Metadata{Host: "cdn.video.example"}, group.rules))
		require.Equal(t, int64(200_000), group.switchMargin)
		require.Equal(t, 9*time.Second, group.targetCooldown)
		require.Equal(t, time.Minute, group.stateTTL)
		require.Equal(t, 7, group.maxStates)
		require.True(t, group.exploration.enabled)
		require.Equal(t, uint64(17), group.exploration.interval)
		require.True(t, group.gray.isEnabled())
		require.True(t, group.media.enabled)
		require.Equal(t, vaneDefaultMediaLowWindows, group.media.lowWindows)
		require.Equal(t, vaneDefaultMediaMaxLowWindows, group.media.maxLowWindows)
		require.Equal(t, []string{"video.example"}, group.media.domains)
		require.Equal(t, float64(2_000_000), group.media.demandBPS)
	})

	t.Run("prior model configuration is rejected", func(t *testing.T) {
		proxyMap, providerMap := newInputs()
		_, err := ParseProxyGroup(map[string]any{
			"name":        "vane-no-model",
			"type":        "vane",
			"proxies":     []string{"alpha"},
			"prior-model": "obsolete.json",
		}, proxyMap, providerMap, nil, nil)
		require.ErrorContains(t, err, "prior-model is not supported by vane")
	})

	t.Run("provider-only group resolves the provider health URL before registration", func(t *testing.T) {
		proxyMap, providerMap := newInputs()
		provider := newVaneTestProvider(newVaneTestProxy("remote", true, true))
		provider.name = "remote-provider"
		provider.healthURL = "https://provider.example/generate_204"
		providerMap[provider.name] = provider
		parsed, err := ParseProxyGroup(map[string]any{
			"name":           "vane-provider-only",
			"type":           "vane",
			"use":            []string{provider.name},
			"empty-fallback": "fallback",
			"filter":         "remote",
		}, proxyMap, providerMap, nil, nil)
		require.NoError(t, err)
		group := parsed.(*Vane)
		require.Equal(t, provider.healthURL, group.testURL)
		provider.mu.Lock()
		registrations := append([]vaneTestHealthRegistration(nil), provider.registered...)
		provider.mu.Unlock()
		require.Equal(t, []vaneTestHealthRegistration{{
			url: provider.healthURL, filter: "remote", interval: 300,
		}}, registrations)
	})

	t.Run("explicit provider URL is registered once after interval defaulting", func(t *testing.T) {
		proxyMap, providerMap := newInputs()
		provider := newVaneTestProvider(newVaneTestProxy("remote", true, true))
		provider.name = "explicit-provider"
		providerMap[provider.name] = provider
		const testURL = "https://health.example/generate_204"
		parsed, err := ParseProxyGroup(map[string]any{
			"name":           "vane-explicit-provider",
			"type":           "vane",
			"use":            []string{provider.name},
			"url":            testURL,
			"empty-fallback": "fallback",
		}, proxyMap, providerMap, nil, nil)
		require.NoError(t, err)
		require.IsType(t, &Vane{}, parsed)
		provider.mu.Lock()
		registrations := append([]vaneTestHealthRegistration(nil), provider.registered...)
		provider.mu.Unlock()
		require.Equal(t, []vaneTestHealthRegistration{{url: testURL, interval: 300}}, registrations)
	})

	t.Run("mixed explicit proxies and provider preserve one resolved registration", func(t *testing.T) {
		proxyMap, providerMap := newInputs()
		provider := newVaneTestProvider(newVaneTestProxy("remote", true, true))
		provider.name = "mixed-provider"
		providerMap[provider.name] = provider
		parsed, err := ParseProxyGroup(map[string]any{
			"name":           "vane-mixed",
			"type":           "vane",
			"proxies":        []string{"alpha"},
			"use":            []string{provider.name},
			"empty-fallback": "fallback",
		}, proxyMap, providerMap, nil, nil)
		require.NoError(t, err)
		group := parsed.(*Vane)
		require.ElementsMatch(t, []string{"alpha", "remote"}, proxyNames(group.Proxies()))
		provider.mu.Lock()
		registrations := append([]vaneTestHealthRegistration(nil), provider.registered...)
		provider.mu.Unlock()
		require.Equal(t, []vaneTestHealthRegistration{{url: C.DefaultTestURL, interval: 300}}, registrations)
	})

	invalid := []struct {
		name  string
		field string
		value any
	}{
		{"negative switch margin", "switch-margin", -0.1},
		{"switch margin above one", "switch-margin", 1.1},
		{"negative target cooldown", "target-cooldown", -1},
		{"target cooldown too large", "target-cooldown", vaneMaximumConfigSeconds + 1},
		{"negative state ttl", "state-ttl", -1},
		{"state ttl too large", "state-ttl", vaneMaximumConfigSeconds + 1},
		{"negative max states", "max-states", -1},
		{"invalid scene rule", "scene-rules", []string{"DOMAIN,example.com,invalid"}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			proxyMap, providerMap := newInputs()
			config := map[string]any{
				"name":           "vane-invalid",
				"type":           "vane",
				"proxies":        []string{"alpha"},
				"empty-fallback": "fallback",
			}
			config[test.field] = test.value
			_, err := ParseProxyGroup(config, proxyMap, providerMap, nil, nil)
			require.Error(t, err)
		})
	}
}

func TestVaneCandidateEligibilityAndDeterminism(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &vaneFakeClock{now: now}

	t.Run("alive candidates win over unhealthy candidates", func(t *testing.T) {
		dead := newVaneTestProxy("a-dead", false, true)
		alive := newVaneTestProxy("z-alive", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, dead, alive)
		require.Equal(t, alive.Name(), group.pick(nil, vaneTransportTCP, false, false).Name())
	})

	t.Run("all unhealthy deterministically falls back to all candidates", func(t *testing.T) {
		beta := newVaneTestProxy("beta", false, true)
		alpha := newVaneTestProxy("alpha", false, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, beta, alpha)
		for i := 0; i < 100; i++ {
			require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, false).Name())
		}
	})

	t.Run("udp capability is filtered before ranking", func(t *testing.T) {
		tcpOnly := newVaneTestProxy("alpha", true, false)
		udp := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, tcpOnly, udp)
		require.Equal(t, "beta", group.pick(&C.Metadata{NetWork: C.UDP}, vaneTransportUDP, false, false).Name())
	})

	t.Run("no udp compatible candidate uses configured fallback", func(t *testing.T) {
		tcpOnly := newVaneTestProxy("alpha", true, false)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, tcpOnly)
		require.Equal(t, "fallback", group.pick(&C.Metadata{NetWork: C.UDP}, vaneTransportUDP, false, false).Name())
	})

	t.Run("provider order cannot change equal-score selection", func(t *testing.T) {
		charlie := newVaneTestProxy("charlie", true, true)
		alpha := newVaneTestProxy("alpha", true, true)
		bravo := newVaneTestProxy("bravo", true, true)
		group, provider := newVaneGroupForTest(clock, 10, time.Hour, charlie, alpha, bravo)
		for i := 0; i < 100; i++ {
			if i%2 == 0 {
				provider.setProxies(bravo, charlie, alpha)
			} else {
				provider.setProxies(charlie, alpha, bravo)
			}
			require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, false).Name())
		}
	})
}

func TestVaneSoftAnchorStrictMarginPerTransportAndScene(t *testing.T) {
	scenes := []struct {
		name  string
		scene vaneScene
		host  string
		rule  string
	}{
		{"default", vaneSceneDefault, "default.example", ""},
		{"interactive", vaneSceneInteractive, "interactive.example", "DOMAIN,interactive.example,interactive"},
		{"media", vaneSceneMedia, "media.example", "DOMAIN,media.example,media"},
		{"bulk", vaneSceneBulk, "bulk.example", "DOMAIN,bulk.example,bulk"},
	}
	transports := []struct {
		name      string
		transport vaneTransport
		network   C.NetWork
	}{
		{"tcp", vaneTransportTCP, C.TCP},
		{"udp", vaneTransportUDP, C.UDP},
	}

	for _, sceneTest := range scenes {
		for _, transportTest := range transports {
			t.Run(sceneTest.name+"/"+transportTest.name, func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				clock := &vaneFakeClock{now: now}
				anchor := newVaneTestProxy("anchor", true, true)
				challenger := newVaneTestProxy("challenger", true, true)
				group, _ := newVaneGroupForTest(clock, 10, time.Hour, anchor, challenger)
				if sceneTest.rule != "" {
					rules, err := parseVaneSceneRules([]string{sceneTest.rule})
					require.NoError(t, err)
					group.rules = rules
				}
				metadata := &C.Metadata{Host: sceneTest.host, NetWork: transportTest.network, DstPort: 443}
				weight := vaneScoring(sceneTest.scene).failureWeight
				// 0.9 leaves room for the value step 0.05/weight that every scene
				// weight now needs; the score step itself is always exactly 5%.
				anchorFailure := 0.9
				margin := 0.05
				exactFailure := anchorFailure - margin/weight
				wantMargin := int64(math.Round(1_000_000 * margin))
				setVaneFailureForTest(group, "anchor", transportTest.transport, now, anchorFailure)
				setVaneFailureForTest(group, "challenger", transportTest.transport, now, exactFailure)
				key := vaneAnchorKey{transport: transportTest.transport, scene: sceneTest.scene}
				group.anchors[key] = vaneAnchor{name: "anchor"}

				anchorScore := scoreVaneMetrics(sceneTest.scene, group.nodes["anchor"].snapshot(transportTest.transport, now))
				challengerScore := scoreVaneMetrics(sceneTest.scene, group.nodes["challenger"].snapshot(transportTest.transport, now))
				require.Equal(t, wantMargin, anchorScore-challengerScore)
				require.Equal(t, "anchor", group.pick(metadata, transportTest.transport, false, true).Name(), "an exact margin must not switch")

				setVaneFailureForTest(group, "challenger", transportTest.transport, now, exactFailure-0.00001)
				challengerScore = scoreVaneMetrics(sceneTest.scene, group.nodes["challenger"].snapshot(transportTest.transport, now))
				require.Greater(t, anchorScore-challengerScore, wantMargin)
				require.Equal(t, "challenger", group.pick(metadata, transportTest.transport, false, true).Name(), "a strictly larger margin must switch")
			})
		}
	}
}

func TestVaneTargetCooldownScopeAndAllCooledFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &vaneFakeClock{now: now}
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	target := &C.Metadata{Host: "one.example", DstPort: 443, NetWork: C.TCP}
	otherHost := &C.Metadata{Host: "two.example", DstPort: 443, NetWork: C.TCP}
	otherPort := &C.Metadata{Host: "one.example", DstPort: 8443, NetWork: C.TCP}

	group.recordDialFailure(context.Background(), target, vaneTransportTCP, alpha, errors.New("refused"), clock.Now())
	clearVaneMetricsForTest(group)
	anchorKey := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneDefault}
	group.anchors[anchorKey] = vaneAnchor{name: "alpha"}
	require.Equal(t, "beta", group.pick(target, vaneTransportTCP, false, true).Name())
	require.Equal(t, "alpha", group.anchors[anchorKey].name, "target cooldown must bypass rather than replace the global anchor")
	require.Equal(t, "alpha", group.pick(otherHost, vaneTransportTCP, false, false).Name())
	require.Equal(t, "alpha", group.pick(otherPort, vaneTransportTCP, false, false).Name())

	clock.Add(time.Second)
	group.recordDialFailure(context.Background(), target, vaneTransportTCP, beta, errors.New("refused"), clock.Now())
	clearVaneMetricsForTest(group)
	require.Equal(t, "alpha", group.pick(target, vaneTransportTCP, false, false).Name(), "when all candidates cool down, the earliest expiry must win")
}

func TestVaneNeutralDialErrorsDoNotPolluteMetricsOrCooldown(t *testing.T) {
	tests := []struct {
		name string
		err  error
		ctx  func() context.Context
	}{
		{"ErrNotSupport", C.ErrNotSupport, context.Background},
		{"canceled", context.Canceled, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
			proxy := newVaneTestProxy("only", true, true)
			proxy.dialErr = test.err
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
			_, err := group.DialContext(test.ctx(), &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.TCP})
			require.ErrorIs(t, err, test.err)
			require.Empty(t, group.cooldowns)
			state := group.nodes[proxy.Name()]
			require.NotNil(t, state, "selection may create bounded candidate state")
			snapshot := state.snapshot(vaneTransportTCP, clock.Now())
			require.False(t, snapshot.failure.valid)
			require.False(t, snapshot.connect.valid)
		})
	}
}

func TestVaneTargetFailureDoesNotReplaceOtherTargetAnchor(t *testing.T) {
	clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	anchorKey := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneDefault}
	group.anchors[anchorKey] = vaneAnchor{name: alpha.Name()}
	failedTarget := &C.Metadata{Host: "failed.example", DstPort: 443, NetWork: C.TCP}
	otherTarget := &C.Metadata{Host: "other.example", DstPort: 443, NetWork: C.TCP}

	group.recordDialFailure(context.Background(), failedTarget, vaneTransportTCP, alpha, errors.New("refused"), clock.Now())
	setVaneFailureForTest(group, alpha.Name(), vaneTransportTCP, clock.Now(), 1)
	setVaneFailureForTest(group, beta.Name(), vaneTransportTCP, clock.Now(), 0)
	require.Equal(t, beta.Name(), group.pick(otherTarget, vaneTransportTCP, false, true).Name())
	require.Equal(t, alpha.Name(), group.anchors[anchorKey].name,
		"target-scoped evidence may bypass but must not replace the global anchor while cooling")
}

func TestVaneDeadlineFailureIsNotNeutral(t *testing.T) {
	clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
	proxy := newVaneTestProxy("only", true, true)
	proxy.dialErr = context.DeadlineExceeded
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	metadata := &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.TCP}

	_, err := group.DialContext(ctx, metadata)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Len(t, group.cooldowns, 1)
	snapshot := group.nodes[proxy.Name()].snapshot(vaneTransportTCP, clock.Now())
	require.True(t, snapshot.failure.valid)
	require.InDelta(t, 1, snapshot.failure.value, 1e-12)
}

func TestGroupBaseConcurrentSuccessAndHealthReset(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("node", true, true))
	group.failedTestMux.Lock()
	group.failedTimes = 7
	group.failedTestMux.Unlock()

	const workers = 128
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func(runHealthCheck bool) {
			defer wait.Done()
			<-start
			if runHealthCheck {
				group.healthCheck()
				return
			}
			group.onDialSuccess()
		}(i%4 == 0)
	}
	close(start)
	wait.Wait()
	group.failedTestMux.Lock()
	defer group.failedTestMux.Unlock()
	require.Zero(t, group.failedTimes)
}

func TestVanePublicSurfaceAndBoundedCleanup(t *testing.T) {
	clock := newVaneConnTestClock()
	udpProxy := newVaneTestProxy("udp", true, true)
	group, provider := newVaneGroupForTest(clock, 2, time.Hour, udpProxy)

	require.True(t, group.SupportUDP())
	group.disableUDP = true
	require.False(t, group.SupportUDP())
	group.disableUDP = false
	require.False(t, group.IsL3Protocol(&C.Metadata{}))
	require.Equal(t, []P.ProxyProvider{provider}, group.Providers())
	delays, err := group.URLTest(context.Background(), C.DefaultTestURL, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]uint16{"udp": 1}, delays)

	target, port := vaneTarget(&C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
	require.Equal(t, "example.com", target)
	require.Equal(t, uint16(443), port)
	target, port = vaneTarget(&C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
	require.Equal(t, "192.0.2.1", target)
	require.Equal(t, uint16(443), port)
	target, port = vaneTarget(nil)
	require.Empty(t, target)
	require.Zero(t, port)
	require.Zero(t, vaneElapsed(clock.Now(), clock.Now().Add(-time.Second)))

	noUDP, _ := newVaneGroupForTest(clock, 2, time.Hour, newVaneTestProxy("tcp", true, false))
	require.False(t, noUDP.SupportUDP())

	now := clock.Now()
	group.cooldowns[vaneCooldownKey{target: "expired"}] = now
	for i := 0; i < vaneDefaultMaxCooldowns+8; i++ {
		key := vaneCooldownKey{target: fmt.Sprintf("target-%04d", i), candidate: "udp"}
		group.cooldowns[key] = now.Add(time.Duration(i+1) * time.Second)
	}
	group.mu.Lock()
	group.pruneCooldownsLocked(now)
	group.mu.Unlock()
	require.Len(t, group.cooldowns, vaneDefaultMaxCooldowns)
	require.NotContains(t, group.cooldowns, vaneCooldownKey{target: "expired"})
}

func TestVaneDeferredTCPHandshakeSettlement(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{
		reads: []vaneConnTestRead{{payload: []byte("response")}},
	}}
	proxy := newVaneTestProxy("node", true, true)
	proxy.dialConn = underlying
	proxy.dialHook = func() { clock.Advance(10 * time.Millisecond) }
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
	metadata := &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.TCP}

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	group.mu.Lock()
	beforeWrite := group.nodes[proxy.Name()].snapshot(vaneTransportTCP, clock.Now())
	group.mu.Unlock()
	require.False(t, beforeWrite.failure.valid)
	require.InDelta(t, math.Log(10), beforeWrite.connect.value, 1e-12)

	clock.Advance(20 * time.Millisecond)
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	clock.Advance(30 * time.Millisecond)
	_, err = conn.Read(make([]byte, 32))
	require.NoError(t, err)
	group.mu.Lock()
	afterRead := group.nodes[proxy.Name()].snapshot(vaneTransportTCP, clock.Now())
	group.mu.Unlock()
	require.True(t, afterRead.failure.valid)
	require.InDelta(t, 0, afterRead.failure.value, 1e-12)
	require.InDelta(t, math.Log(30), afterRead.response.value, 1e-12)
}

func TestVaneProductionDialAndPacketFeedback(t *testing.T) {
	t.Run("tcp success records setup response and chain on the real group path", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{{payload: []byte("response")}}}
		proxy := newVaneTestProxy("node", true, true)
		proxy.dialConn = underlying
		proxy.dialHook = func() { clock.Advance(120 * time.Millisecond) }
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		metadata := &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.TCP}

		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		require.Equal(t, C.Chain{"vane-test"}, conn.Chains())
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		clock.Advance(80 * time.Millisecond)
		_, err = conn.Read(make([]byte, 32))
		require.NoError(t, err)

		group.mu.Lock()
		snapshot := group.nodes[proxy.Name()].snapshot(vaneTransportTCP, clock.Now())
		group.mu.Unlock()
		require.True(t, snapshot.failure.valid)
		require.InDelta(t, 0, snapshot.failure.value, 1e-12)
		require.InDelta(t, math.Log(120), snapshot.connect.value, 1e-12)
		require.InDelta(t, math.Log(80), snapshot.response.value, 1e-12)
		require.Empty(t, group.cooldowns)
	})

	t.Run("udp success is settled only by the first positive datagram", func(t *testing.T) {
		clock := newVaneConnTestClock()
		packet := &vanePacketConnTestFake{}
		proxy := newVaneTestProxy("node", true, true)
		proxy.packetConn = packet
		proxy.packetHook = func() { clock.Advance(25 * time.Millisecond) }
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		metadata := &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.UDP}

		conn, err := group.ListenPacketContext(context.Background(), metadata)
		require.NoError(t, err)
		require.Equal(t, C.Chain{"vane-test"}, conn.Chains())
		group.mu.Lock()
		beforeWrite := group.nodes[proxy.Name()].snapshot(vaneTransportUDP, clock.Now())
		group.mu.Unlock()
		require.False(t, beforeWrite.failure.valid)
		require.InDelta(t, math.Log(25), beforeWrite.connect.value, 1e-12)

		_, err = conn.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
		require.NoError(t, err)
		group.mu.Lock()
		afterWrite := group.nodes[proxy.Name()].snapshot(vaneTransportUDP, clock.Now())
		group.mu.Unlock()
		require.True(t, afterWrite.failure.valid)
		require.InDelta(t, 0, afterWrite.failure.value, 1e-12)
	})
}

func TestVaneProductionUDPResponseBeforeWriteErrorIsSuccess(t *testing.T) {
	clock := newVaneConnTestClock()
	writeEntered := make(chan struct{})
	releaseWrite := make(chan struct{})
	packet := &vanePacketConnTestFake{
		writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			close(writeEntered)
			<-releaseWrite
			return len(payload), errVaneTestWrite
		},
		readFromFunc: func(payload []byte) (int, net.Addr, error) {
			return copy(payload, []byte("response")), vaneConnTestAddr("source"), nil
		},
	}
	proxy := newVaneTestProxy("node", true, true)
	proxy.packetConn = packet
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
	metadata := &C.Metadata{Host: "target.example", DstPort: 443, NetWork: C.UDP}
	conn, err := group.ListenPacketContext(context.Background(), metadata)
	require.NoError(t, err)

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = conn.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
	}()
	<-writeEntered
	n, _, readErr := conn.ReadFrom(make([]byte, 32))
	require.NoError(t, readErr)
	require.Positive(t, n)
	close(releaseWrite)
	<-writeDone

	group.mu.Lock()
	snapshot := group.nodes[proxy.Name()].snapshot(vaneTransportUDP, clock.Now())
	group.mu.Unlock()
	require.True(t, snapshot.failure.valid)
	require.InDelta(t, 0, snapshot.failure.value, 1e-12)
	require.Empty(t, group.cooldowns)
}

func TestVaneProviderRemovalInvalidatesAnchor(t *testing.T) {
	clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, beta, alpha)

	require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, true).Name())
	key := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneDefault}
	require.Equal(t, "alpha", group.anchors[key].name)

	provider.setProxies(beta)
	require.Equal(t, "beta", group.pick(nil, vaneTransportTCP, false, true).Name())
	require.Equal(t, "beta", group.anchors[key].name)
}

func TestVaneReadOnlyViewsDoNotMutatePolicyState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := &vaneFakeClock{now: now}
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, beta, alpha)
	setVaneFailureForTest(group, "alpha", vaneTransportTCP, now, 0.25)
	key := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneDefault}
	group.anchors[key] = vaneAnchor{name: "alpha", scoreMicros: 123}
	cooldownKey := vaneCooldownKey{transport: vaneTransportTCP, target: "future.example", port: 443, candidate: "beta"}
	group.cooldowns[cooldownKey] = now.Add(time.Hour)
	beforeLastSeen := group.nodes["alpha"].lastObservedAt
	beforeMetrics := group.nodes["alpha"].snapshot(vaneTransportTCP, now)

	require.Equal(t, "alpha", group.Unwrap(&C.Metadata{Host: "example.com", DstPort: 443}, true).Name())
	require.Equal(t, "alpha", group.Now())
	payload, err := group.MarshalJSON()
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(payload, &body))
	require.Equal(t, "Vane", body["type"])
	require.Equal(t, "alpha", body["now"])
	require.Equal(t, "fallback", body["emptyFallback"])
	require.ElementsMatch(t, []any{"alpha", "beta"}, body["all"])

	require.Len(t, group.nodes, 1)
	require.Equal(t, beforeLastSeen, group.nodes["alpha"].lastObservedAt)
	require.Equal(t, beforeMetrics, group.nodes["alpha"].snapshot(vaneTransportTCP, now))
	require.Equal(t, vaneAnchor{name: "alpha", scoreMicros: 123}, group.anchors[key])
	require.Equal(t, now.Add(time.Hour), group.cooldowns[cooldownKey])
}

func TestVaneStateTTLAndMaxStates(t *testing.T) {
	t.Run("removed candidates expire at ttl", func(t *testing.T) {
		clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, provider := newVaneGroupForTest(clock, 10, 10*time.Second, alpha)
		require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, true).Name())
		provider.setProxies(beta)
		clock.Add(10 * time.Second)
		require.Equal(t, "beta", group.pick(nil, vaneTransportTCP, false, true).Name())
		require.NotContains(t, group.nodes, "alpha")
		require.Contains(t, group.nodes, "beta")
	})

	t.Run("oldest inactive state is evicted at max states", func(t *testing.T) {
		clock := &vaneFakeClock{now: time.Unix(1_700_000_000, 0)}
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		charlie := newVaneTestProxy("charlie", true, true)
		group, provider := newVaneGroupForTest(clock, 2, time.Hour, alpha)
		group.pick(nil, vaneTransportTCP, false, true)
		clock.Add(time.Second)
		provider.setProxies(beta)
		group.pick(nil, vaneTransportTCP, false, true)
		clock.Add(time.Second)
		provider.setProxies(charlie)
		group.pick(nil, vaneTransportTCP, false, true)
		require.Len(t, group.nodes, 1, "generation bindings contain only current provider members")
		require.Contains(t, group.nodes, "charlie")
		group.learning.mu.Lock()
		require.Len(t, group.learning.nodes, 2)
		remaining := make(map[string]struct{}, len(group.learning.nodes))
		for _, state := range group.learning.nodes {
			remaining[state.name] = struct{}{}
		}
		group.learning.mu.Unlock()
		require.NotContains(t, remaining, "alpha")
		require.Contains(t, remaining, "beta")
		require.Contains(t, remaining, "charlie")
	})

	t.Run("active candidates are never evicted to satisfy max states", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		clock := &vaneFakeClock{now: now}
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		charlie := newVaneTestProxy("charlie", true, true)
		group, _ := newVaneGroupForTest(clock, 2, time.Hour, alpha, beta, charlie)
		group.mu.Lock()
		group.ensureNodeLocked("alpha", now)
		group.ensureNodeLocked("beta", now)
		group.ensureNodeLocked("charlie", now)
		group.mu.Unlock()
		group.pick(nil, vaneTransportTCP, false, true)
		require.Len(t, group.nodes, 3)
	})
	t.Run("temporary health and transport filters do not evict configured candidates", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		clock := &vaneFakeClock{now: now}
		healthyUDP := newVaneTestProxy("healthy-udp", true, true)
		unhealthyUDP := newVaneTestProxy("unhealthy-udp", false, true)
		tcpOnly := newVaneTestProxy("tcp-only", true, false)
		group, _ := newVaneGroupForTest(clock, 1, time.Hour, healthyUDP, unhealthyUDP, tcpOnly)
		group.mu.Lock()
		group.ensureNodeLocked(healthyUDP.Name(), now)
		group.ensureNodeLocked(unhealthyUDP.Name(), now)
		group.ensureNodeLocked(tcpOnly.Name(), now)
		group.mu.Unlock()

		group.pick(&C.Metadata{NetWork: C.UDP}, vaneTransportUDP, false, true)
		group.mu.Lock()
		defer group.mu.Unlock()
		require.Contains(t, group.nodes, healthyUDP.Name())
		require.Contains(t, group.nodes, unhealthyUDP.Name())
		require.Contains(t, group.nodes, tcpOnly.Name())
	})
}

func BenchmarkVanePick32(b *testing.B) {
	clock := newVaneConnTestClock()
	proxies := make([]C.Proxy, 32)
	for index := range proxies {
		proxies[index] = newVaneTestProxy(fmt.Sprintf("node-%02d", index), true, true)
	}
	group, _ := newVaneGroupForTest(clock, 256, time.Hour, proxies...)
	metadata := &C.Metadata{Host: "benchmark.example", DstPort: 443, NetWork: C.TCP}
	group.pick(metadata, vaneTransportTCP, false, true)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		group.pick(metadata, vaneTransportTCP, false, true)
	}
}

func setVaneFailureForTest(group *Vane, name string, transport vaneTransport, now time.Time, value float64) {
	const weight = 1_000_000_000.0
	metric := vaneDualMetric{
		fast: vaneDecayLayer{weight: weight, sum: weight * value, updatedAt: now, valid: true},
		slow: vaneDecayLayer{weight: weight, sum: weight * value, updatedAt: now, valid: true},
	}
	group.mu.Lock()
	state := group.ensureNodeLocked(name, now)
	state.metrics(transport).failure = metric
	group.mu.Unlock()
}

func clearVaneMetricsForTest(group *Vane) {
	group.mu.Lock()
	for _, state := range group.nodes {
		state.tcp = vaneMetrics{}
		state.udp = vaneMetrics{}
	}
	group.mu.Unlock()
}

func proxyNames(proxies []C.Proxy) []string {
	names := make([]string, len(proxies))
	for i, proxy := range proxies {
		names[i] = proxy.Name()
	}
	return names
}
