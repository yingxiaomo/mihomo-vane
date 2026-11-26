package outboundgroup

// HASH-PIN acceptance tests: one rule set must keep selecting one node, so a
// page and its video stream never leave on two different IPs.

import (
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

func newVaneHashPinGroup(t *testing.T, names ...string) (*Vane, *vaneConnTestClock, map[string]*vaneTestProxy) {
	t.Helper()
	clock := newVaneConnTestClock()
	proxies := make([]C.Proxy, 0, len(names))
	byName := make(map[string]*vaneTestProxy, len(names))
	for _, name := range names {
		proxy := newVaneTestProxy(name, true, true)
		proxies = append(proxies, proxy)
		byName[name] = proxy
	}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxies...)
	t.Cleanup(func() { _ = group.Close() })
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	return group, clock, byName
}

func vaneHashMetadata(host string) *C.Metadata {
	return &C.Metadata{Host: host, DstPort: 443, NetWork: C.TCP}
}

func installVaneHashRuleSet(t *testing.T, name string, domains ...string) {
	t.Helper()
	oldProviders := tunnel.RuleProviders()
	oldRules := tunnel.Rules()
	provider := RP.NewRuleSetProvider(name, P.Domain, P.YamlRule, 0, nil, domains, nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{name: provider})
	t.Cleanup(func() { tunnel.UpdateRules(oldRules, nil, oldProviders) })
}

func vaneHashPinnedEvents(group *Vane) []vaneRecordedEvent {
	events := make([]vaneRecordedEvent, 0, 4)
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "hash-pinned" {
			events = append(events, event)
		}
	}
	return events
}

func vaneHashBucket(scope string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(scope))
	return h.Sum64()
}

// HASH-01: one RULE-SET covers the page and the stream, so both land on the
// same node. A single GEOSITE is untestable in the sandbox (no geodata), and
// two DOMAIN rules would be two buckets.
func TestVaneHashPinRuleSetKeepsPageAndStreamTogether(t *testing.T) {
	group, clock, _ := newVaneHashPinGroup(t, "a", "b", "c", "d")
	pageHost := "youtube.com"
	streamHost := "rr1---sn-a5meknde.googlevideo.com"

	// Probe provider names until the bucket is not the ranking leader: the
	// control below must be able to tell a pin from two picks agreeing by luck.
	var pinned C.Proxy
	found := false
	for i := 0; i < 32 && !found; i++ {
		name := fmt.Sprintf("vane-hash-yt-%d", i)
		installVaneHashRuleSet(t, name, pageHost, "+.googlevideo.com")
		group.hashRules = []vaneFamilyRule{{kind: vaneRuleRuleSet, value: name}}
		pinned = group.pick(vaneHashMetadata(pageHost), vaneTransportTCP, false, false)
		require.NotNil(t, pinned)
		require.Equal(t, pinned.Name(), group.pick(vaneHashMetadata(streamHost), vaneTransportTCP, false, false).Name(),
			"the rule set must pin both hosts to one node")
		found = pinned.Name() != "a"
	}
	require.True(t, found, "no provider name landed off the ranking leader")

	// Cool the ranking leader for the stream target only: without the pin the
	// page would follow "a" and the stream would move on, so both staying on
	// the pinned node is the pin doing the work.
	group.mu.Lock()
	group.cooldowns[vaneCooldownKey{
		transport: vaneTransportTCP, target: streamHost, port: 443,
		candidate: "a", identity: "test:a",
	}] = clock.Now().Add(time.Hour)
	group.mu.Unlock()
	require.Equal(t, pinned.Name(), group.pick(vaneHashMetadata(pageHost), vaneTransportTCP, false, false).Name())
	require.Equal(t, pinned.Name(), group.pick(vaneHashMetadata(streamHost), vaneTransportTCP, false, false).Name())
}

// HASH-02: a host outside the hash rules is untouched and records nothing.
func TestVaneHashPinMissFallsBackToRanking(t *testing.T) {
	installVaneHashRuleSet(t, "vane-hash-yt", "youtube.com", "+.googlevideo.com")
	group, _, _ := newVaneHashPinGroup(t, "a", "b", "c")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleRuleSet, value: "vane-hash-yt"}}

	group.pick(vaneHashMetadata("t.me"), vaneTransportTCP, true, true)
	require.Empty(t, vaneHashPinnedEvents(group), "an unhashed host must not record a pin")
}

// HASH-03: a cooled pinned node fails over to the next ring position.
func TestVaneHashPinFailsOverOnCooldown(t *testing.T) {
	group, clock, byName := newVaneHashPinGroup(t, "a", "b", "c", "d")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}

	metadata := vaneHashMetadata("youtube.com")
	pinned := group.pick(metadata, vaneTransportTCP, true, false)
	require.NotNil(t, pinned)

	group.mu.Lock()
	group.cooldowns[vaneCooldownKey{
		transport: vaneTransportTCP, target: "youtube.com", port: 443,
		candidate: pinned.Name(), identity: vaneProxyPersistentIdentity(byName[pinned.Name()]),
	}] = clock.Now().Add(time.Hour)
	group.mu.Unlock()

	failedOver := group.pick(metadata, vaneTransportTCP, true, true)
	require.NotEqual(t, pinned.Name(), failedOver.Name())
	events := vaneHashPinnedEvents(group)
	require.Len(t, events, 1)
	require.Equal(t, "failover", events[0].Reason)
	require.Equal(t, "a", events[0].From, "from is the ranking leader, not the pin")
	require.Equal(t, failedOver.Name(), events[0].To)
}

// HASH-04: every candidate cooled still picks something, like before.
func TestVaneHashPinAllCooledStillPicks(t *testing.T) {
	group, clock, byName := newVaneHashPinGroup(t, "a", "b", "c")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}

	group.mu.Lock()
	for name, proxy := range byName {
		group.cooldowns[vaneCooldownKey{
			transport: vaneTransportTCP, target: "youtube.com", port: 443,
			candidate: name, identity: vaneProxyPersistentIdentity(proxy),
		}] = clock.Now().Add(time.Hour)
	}
	group.mu.Unlock()

	selected := group.pick(vaneHashMetadata("youtube.com"), vaneTransportTCP, true, true)
	require.NotNil(t, selected)
	require.Contains(t, byName, selected.Name())
}

// HASH-05: removing a node only remaps the keys on the removed bucket — the
// jump-hash property that keeps pinning stable across provider reloads.
func TestVaneHashPinNodeRemovalOnlyMovesItsBucket(t *testing.T) {
	clock := newVaneConnTestClock()
	group, provider := newVaneGroupForTest(clock, 10, time.Hour,
		newVaneTestProxy("n0", true, true), newVaneTestProxy("n1", true, true),
		newVaneTestProxy("n2", true, true), newVaneTestProxy("n3", true, true))
	t.Cleanup(func() { _ = group.Close() })
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	const buckets = 4

	// One key on the removed (last) bucket and one that is not, so a modulo
	// hash (which remaps nearly everything) cannot pass.
	keys := make([]string, 0, 2)
	var movedKey string
	for i := 0; len(keys) < 2 || movedKey == ""; i++ {
		host := fmt.Sprintf("h%d.test", i)
		if i > 500 {
			t.Fatal("no key landed on the removed bucket")
		}
		if int(jumpHash(vaneHashBucket(host), buckets)) == buckets-1 {
			if movedKey == "" {
				movedKey = host
			}
			continue
		}
		if len(keys) < 4 && host != movedKey {
			keys = append(keys, host)
		}
	}
	keys = append(keys, movedKey)

	group.hashRules = make([]vaneFamilyRule, 0, len(keys))
	for _, key := range keys {
		group.hashRules = append(group.hashRules, vaneFamilyRule{kind: vaneRuleDomain, value: key})
	}
	before := make(map[string]string, len(keys))
	for _, key := range keys {
		before[key] = group.pick(vaneHashMetadata(key), vaneTransportTCP, true, false).Name()
	}

	provider.setProxies(newVaneTestProxy("n0", true, true), newVaneTestProxy("n1", true, true), newVaneTestProxy("n2", true, true))
	for _, key := range keys {
		after := group.pick(vaneHashMetadata(key), vaneTransportTCP, true, false).Name()
		if key == movedKey {
			require.NotEqual(t, before[key], after, "%s sat on the removed bucket and must remap", key)
			continue
		}
		require.Equal(t, before[key], after, "%s must keep its node when another bucket disappears", key)
	}
}

// HASH-06: a pin beats the per-target sticky choice, and the sticky choice
// really would have won without the pin.
func TestVaneHashPinBeatsSticky(t *testing.T) {
	group, clock, byName := newVaneHashPinGroup(t, "a", "b", "c", "d")
	metadata := vaneHashMetadata("youtube.com")

	rankedFirst := group.pick(metadata, vaneTransportTCP, true, false).Name()
	require.Equal(t, "a", rankedFirst, "equal scores rank by name")

	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}
	pinned := group.pick(metadata, vaneTransportTCP, true, false).Name()
	require.NotEqual(t, rankedFirst, pinned, "the pinned bucket must differ from the ranking leader")

	var stickyName string
	for name := range byName {
		if name != rankedFirst && name != pinned {
			stickyName = name
			break
		}
	}
	require.NotEmpty(t, stickyName)

	setSticky := func(name string) {
		group.mu.Lock()
		group.stickiness[vaneStickyKeyFor(metadata.Host, metadata.DstPort)] = vaneStickyChoice{
			name:      name,
			expiresAt: clock.Now().Add(time.Minute),
		}
		group.mu.Unlock()
	}

	setSticky(stickyName)
	require.Equal(t, pinned, group.pick(metadata, vaneTransportTCP, true, false).Name(),
		"with the pin in force the sticky choice must not override it")

	// Control: drop the hash rules and the same sticky choice does win,
	// proving the assertion above is meaningful.
	setSticky(stickyName)
	group.hashRules = nil
	require.Equal(t, stickyName, group.pick(metadata, vaneTransportTCP, true, false).Name(),
		"without the pin the sticky choice must win")
}

func TestVaneHashPinSurvivesExplorationAndColdPick(t *testing.T) {
	t.Run("exploration", func(t *testing.T) {
		group, _, _ := newVaneHashPinGroup(t, "a", "b", "c")
		group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}
		metadata := vaneHashMetadata("youtube.com")
		pinned := group.pick(metadata, vaneTransportTCP, true, false).Name()

		exploration, err := newVaneExplorationConfig(true, 2)
		require.NoError(t, err)
		group.exploration = exploration
		group.mu.Lock()
		group.anchors[vaneAnchorKey{transport: vaneTransportTCP}] = vaneAnchor{name: pinned}
		group.mu.Unlock()

		for i := 0; i < 4; i++ {
			require.Equal(t, pinned, group.pick(metadata, vaneTransportTCP, true, true).Name(),
				"exploration must not move a pinned rule set")
		}
		require.Zero(t, countVaneEvents(group, "exploration-selected", ""))
	})
}

// HASH-08: hash-rules fail fast on a type without a set name or a missing part.
func TestVaneHashPinConfigValidation(t *testing.T) {
	parse := func(rules []string) (*Vane, error) {
		proxyMap := map[string]C.Proxy{
			"COMPATIBLE": A.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "COMPATIBLE", Type: C.Compatible})),
			"fallback":   newVaneTestProxy("fallback", true, false),
			"alpha":      newVaneTestProxy("alpha", true, true),
		}
		providerMap := map[string]P.ProxyProvider{}
		group, err := ParseProxyGroup(map[string]any{
			"name":           "vane-hash",
			"type":           "vane",
			"proxies":        []string{"alpha"},
			"empty-fallback": "fallback",
			"hash-rules":     rules,
		}, proxyMap, providerMap, nil, nil)
		if err != nil {
			return nil, err
		}
		return group.(*Vane), nil
	}

	for _, rules := range [][]string{{"NETWORK,tcp"}, {"GEOSITE"}} {
		_, err := parse(rules)
		require.Error(t, err, "hash-rules %v must be rejected", rules)
	}

	empty, err := parse([]string{})
	require.NoError(t, err)
	require.Empty(t, empty.hashRules)

	pinnedGroup, err := parse([]string{"GEOSITE,youtube"})
	require.NoError(t, err)
	require.Len(t, pinnedGroup.hashRules, 1)
	require.Equal(t, "youtube", pinnedGroup.hashRules[0].scope())
}

// HASH-09: TCP and UDP share one pool, so QUIC cannot leave on another IP.
func TestVaneHashPinSharedAcrossTransports(t *testing.T) {
	t.Run("pinned node speaks UDP", func(t *testing.T) {
		group, _, _ := newVaneHashPinGroup(t, "a", "b", "c", "d")
		group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}
		metadata := vaneHashMetadata("youtube.com")

		tcp := group.pick(metadata, vaneTransportTCP, true, false)
		udp := group.pick(metadata, vaneTransportUDP, true, false)
		require.Equal(t, tcp.Name(), udp.Name())
	})

	t.Run("pinned node has no UDP", func(t *testing.T) {
		const scope = "youtube.com"
		clock := newVaneConnTestClock()
		proxies := make([]C.Proxy, 0, 4)
		var pinnedTarget *vaneTestProxy
		idx := int(jumpHash(vaneHashBucket(scope), 4))
		for i := 0; i < 4; i++ {
			proxy := newVaneTestProxy(fmt.Sprintf("n%d", i), true, i != idx)
			if i == idx {
				pinnedTarget = proxy
			}
			proxies = append(proxies, proxy)
		}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxies...)
		t.Cleanup(func() { _ = group.Close() })
		t.Cleanup(func() { dropVaneRecordedEvents(group) })
		group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: scope}}
		metadata := vaneHashMetadata(scope)

		require.Equal(t, pinnedTarget.Name(), group.pick(metadata, vaneTransportTCP, true, false).Name())
		udp := group.pick(metadata, vaneTransportUDP, true, false)
		require.NotEqual(t, pinnedTarget.Name(), udp.Name(), "a UDP pick cannot use a node without UDP")
	})
}

// HASH-10: an all-TCP group on a UDP pick degrades instead of panicking.
func TestVaneHashPinUDPWithoutAnyUDPNode(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour,
		newVaneTestProxy("a", true, false), newVaneTestProxy("b", true, false))
	t.Cleanup(func() { _ = group.Close() })
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}

	require.NotPanics(t, func() {
		selected := group.pick(vaneHashMetadata("youtube.com"), vaneTransportUDP, true, true)
		require.Equal(t, "fallback", selected.Name())
	})
}

// HASH-11: the latency cap applies to the pin as well (the pool must carry
// hardCapped into its entries).
func TestVaneHashPinSkipsLatencyCappedNode(t *testing.T) {
	group, clock, byName := newVaneHashPinGroup(t, "a", "b", "c", "d")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}
	metadata := vaneHashMetadata("youtube.com")

	pinned := group.pick(metadata, vaneTransportTCP, true, false)
	group.mu.Lock()
	state := group.ensureProxyNodeLocked(pinned, clock.Now())
	state.latencyMs = 400
	state.latencySamples = 10
	state.latencyAt = clock.Now()
	group.mu.Unlock()
	require.Equal(t, byName[pinned.Name()].Name(), pinned.Name())

	slower := group.pick(metadata, vaneTransportTCP, true, true)
	require.NotEqual(t, pinned.Name(), slower.Name(), "a node over the RTT cap must not be pinned")
	events := vaneHashPinnedEvents(group)
	require.Len(t, events, 1)
	require.Equal(t, "failover", events[0].Reason)
}

// HASH-12: a pin is per rule set, so it must not rewrite the scene anchor.
func TestVaneHashPinDoesNotWriteAnchor(t *testing.T) {
	group, _, byName := newVaneHashPinGroup(t, "a", "b", "c", "d")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomain, value: "youtube.com"}}
	metadata := vaneHashMetadata("youtube.com")

	pinned := group.pick(metadata, vaneTransportTCP, true, false).Name()
	anchorName := "a"
	if pinned == anchorName {
		anchorName = "d"
	}
	require.NotEqual(t, anchorName, pinned)

	anchorKey := vaneAnchorKey{transport: vaneTransportTCP}
	group.mu.Lock()
	group.anchors[anchorKey] = vaneAnchor{name: anchorName}
	group.mu.Unlock()

	require.Equal(t, pinned, group.pick(metadata, vaneTransportTCP, true, true).Name())
	group.mu.Lock()
	stored := group.anchors[anchorKey].name
	group.mu.Unlock()
	require.Equal(t, anchorName, stored, "a pinned selection must not become the scene anchor")
	require.Contains(t, byName, stored)
}

// HASH-13: a node the watchdog demoted must not be re-selected through the pin,
// or the pin would keep a demoted node alive forever. Once the per-scene gate
// is gone the demotion applies to every scene, so the pin fails over for a
// plain flow too.
func TestVaneHashPinSkipsMediaCooledNode(t *testing.T) {
	group, clock, byName := newVaneHashPinGroup(t, "a", "b", "c", "d")
	group.mu.Lock()
	group.coolNodeLocked("a", clock.Now().Add(time.Hour), true)
	group.mu.Unlock()

	cand := &vaneRankedProxy{proxy: byName["a"]}
	cand.name = "a"
	require.False(t, group.hashCandidateUsableLocked(cand, vaneTransportTCP, clock.Now(), true),
		"a media-cooled node must be refused for a flow")
	require.False(t, group.hashCandidateUsableLocked(cand, vaneTransportTCP, clock.Now(), true),
		"a demoted node is refused for every scene now that the per-scene gate is gone")

	// The end-to-end path agrees: the pin fails over instead of reusing it.
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomainSuffix, value: "googlevideo.com"}}
	metadata := vaneHashMetadata("rr1.googlevideo.com")
	failedOver := group.pick(metadata, vaneTransportTCP, false, true)
	require.NotNil(t, failedOver)
	require.NotEqual(t, "a", failedOver.Name(), "the pin must fail over off the media-cooled node")
}

// HASH-PIN-MEDIA: an explicit hash pin outranks a media handoff hint, otherwise
// every reconnect inside a pinned rule set would silently move the flow.
func TestVaneHashPinOutranksMediaHint(t *testing.T) {
	group, clock, _ := newVaneHashPinGroup(t, "alpha", "beta", "gamma")
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	group.hashRules = []vaneFamilyRule{{kind: vaneRuleDomainSuffix, value: "googlevideo.com"}}
	metadata := vaneHashMetadata("rr1.googlevideo.com")

	pinned := group.pick(metadata, vaneTransportTCP, false, true)
	require.NotNil(t, pinned)
	require.NotEqual(t, "beta", pinned.Name(), "the pin must not land on beta for this test to mean anything")

	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	require.NotEmpty(t, key.target)
	group.hints[key] = vaneHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute)}

	require.Equal(t, pinned.Name(), group.pick(metadata, vaneTransportTCP, false, true).Name(),
		"the pin outranks the hint")

	// Without a pin the hint still wins, which proves the hint was live.
	group.hashRules = nil
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name())
}
