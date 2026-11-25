package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

// SCENE-GATE-001: a scene rule that carries a target identity opens the media
// gate by itself, so a service only has to be named once (in scene-rules).

func TestVaneSceneGateScopeByRuleKind(t *testing.T) {
	cases := []struct {
		name string
		rule vaneSceneRule
		want string
	}{
		{"domain", vaneSceneRule{kind: vaneRuleDomain, value: "example.com", scene: vaneSceneMedia}, "example.com"},
		{"domain suffix", vaneSceneRule{kind: vaneRuleDomainSuffix, value: "googlevideo.com", scene: vaneSceneMedia}, "googlevideo.com"},
		{"rule set", vaneSceneRule{kind: vaneRuleRuleSet, value: "streaming", scene: vaneSceneMedia}, "streaming"},
		{"geosite", vaneSceneRule{kind: vaneRuleGeoSite, value: "telegram", scene: vaneSceneMedia}, "telegram"},
		{"network", vaneSceneRule{kind: vaneRuleNetwork, scene: vaneSceneMedia}, ""},
		{"dst port", vaneSceneRule{kind: vaneRuleDstPort, scene: vaneSceneMedia}, ""},
		{"in name", vaneSceneRule{kind: vaneRuleInName, values: []string{"chrome"}, scene: vaneSceneMedia}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.rule.scope())
		})
	}
}

func TestVaneSceneGateFirstMatchWins(t *testing.T) {
	rules := []vaneSceneRule{
		{kind: vaneRuleDomain, value: "api.example.com", scene: vaneSceneInteractive},
		{kind: vaneRuleDomainSuffix, value: "example.com", scene: vaneSceneMedia},
	}
	matched, ok := matchVaneSceneRule(&C.Metadata{Host: "api.example.com"}, rules)
	require.True(t, ok)
	require.Equal(t, vaneSceneInteractive, matched.scene, "the first matching rule wins")

	matched, ok = matchVaneSceneRule(&C.Metadata{Host: "www.example.com"}, rules)
	require.True(t, ok)
	require.Equal(t, vaneSceneMedia, matched.scene, "a host past the first rule falls to the suffix rule")

	_, ok = matchVaneSceneRule(&C.Metadata{Host: "unrelated.test"}, rules)
	require.False(t, ok)

	_, ok = matchVaneSceneRule(nil, rules)
	require.False(t, ok, "nil metadata never matches")
}

// sceneGateGroup builds a group whose only gate source is scene-rules: all
// three media gate lists are empty.
func sceneGateGroup(t *testing.T, rules ...vaneSceneRule) *Vane {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.rules = rules
	group.media.domains = nil
	group.media.ruleSets = nil
	group.media.geoSites = nil
	return group
}

func TestVaneSceneGateFallsBackToSceneRule(t *testing.T) {
	oldProviders := tunnel.RuleProviders()
	oldRules := tunnel.Rules()
	provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
		[]string{"+.netflix.com"}, nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
	defer tunnel.UpdateRules(oldRules, nil, oldProviders)

	group := sceneGateGroup(t,
		vaneSceneRule{kind: vaneRuleDomainSuffix, value: "googlevideo.com", scene: vaneSceneMedia},
		vaneSceneRule{kind: vaneRuleRuleSet, value: "streaming", scene: vaneSceneMedia},
		vaneSceneRule{kind: vaneRuleGeoSite, value: "telegram", scene: vaneSceneMedia},
		vaneSceneRule{kind: vaneRuleDomain, value: "plain.example", scene: vaneSceneInteractive},
		vaneSceneRule{kind: vaneRuleNetwork, network: C.UDP, scene: vaneSceneMedia},
	)

	require.Equal(t, "googlevideo.com", group.mediaTargetKey("rr1.googlevideo.com", 443).target,
		"a DOMAIN-SUFFIX scene rule supplies its domain as the scope")
	require.Equal(t, "streaming", group.mediaTargetKey("www.netflix.com", 443).target,
		"a RULE-SET scene rule supplies the provider name as the scope")
	require.Empty(t, group.mediaTargetKey("api.telegram.org", 443).target,
		"a GEOSITE rule cannot resolve without a database in the sandbox (fail-closed)")
	require.Empty(t, group.mediaTargetKey("plain.example", 443).target,
		"a non-media scene rule never opens the gate")
	require.Empty(t, group.mediaTargetKey("other.example", 443).target,
		"a host matching no rule keeps the empty scope")
}

// A gate entry that cannot resolve (unregistered provider, missing GeoSite
// database) is skipped rather than failing, so the scene fallback still
// decides — exactly the fail-closed behaviour the gate lists already had.
func TestVaneSceneGateSkipsUnresolvableEntries(t *testing.T) {
	group := sceneGateGroup(t, vaneSceneRule{kind: vaneRuleDomainSuffix, value: "googlevideo.com", scene: vaneSceneMedia})
	group.media.ruleSets = []string{"missing-provider"}
	group.media.geoSites = []string{"telegram"}

	require.Equal(t, "googlevideo.com", group.mediaTargetKey("rr1.googlevideo.com", 443).target,
		"both unresolvable gate entries are skipped and the scene rule still opens the gate")
	require.Empty(t, group.mediaTargetKey("other.example", 443).target,
		"with no gate hit and no scene match the scope stays empty")
}

// A target with no scope has no media hint: the empty key is the "not
// gate-eligible" case, and every consumer must treat it as a miss.
func TestVaneSceneGateNoHintWithoutScope(t *testing.T) {
	group := sceneGateGroup(t, vaneSceneRule{kind: vaneRuleDomainSuffix, value: "googlevideo.com", scene: vaneSceneMedia})

	require.Empty(t, normalizeVaneMediaTarget(""), "an empty target normalizes to no scope")

	group.mu.Lock()
	proxy, token := group.takeMediaHintLocked("other.example", 443, nil, group.clock.Now(), false)
	group.mu.Unlock()
	require.Nil(t, proxy)
	require.Nil(t, token)
}

func TestVaneSceneGateKeepsGatePrecedence(t *testing.T) {
	oldProviders := tunnel.RuleProviders()
	oldRules := tunnel.Rules()
	provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
		[]string{"+.netflix.com"}, nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
	defer tunnel.UpdateRules(oldRules, nil, oldProviders)

	group := sceneGateGroup(t, vaneSceneRule{kind: vaneRuleDomainSuffix, value: "netflix.com", scene: vaneSceneMedia})
	group.media.ruleSets = []string{"streaming"}

	require.Equal(t, "streaming", group.mediaTargetKey("www.netflix.com", 443).target,
		"a configured gate entry wins over the scene-derived scope")
}

func TestVaneSceneGateBuildsMediaFlowWithoutGate(t *testing.T) {
	group := sceneGateGroup(t, vaneSceneRule{kind: vaneRuleDomainSuffix, value: "googlevideo.com", scene: vaneSceneMedia})

	flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow, "a media flow must be built with no media-reconnect-domains set")
	require.Equal(t, "googlevideo.com", flow.targetKey.target)

	outside := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "other.example", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, outside, "PHASE1: every TCP flow is watched")
	require.False(t, outside.flowMedia, "a host outside every media rule is not a media flow")
	outside.releaseActiveFlowCount()
}
