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

// Vane delegates host matching for RULE-SET scene rules and RULE-SET media
// gate entries to the shared provider, so a label-boundary regression there
// opens the media gate for lookalike hosts. These assertions pin the domain-set
// semantics Vane relies on: "+.example.com" covers the apex and its
// subdomains, and never a host that merely ends with the same text.
func TestVaneRuleSetDomainSetSemantics(t *testing.T) {
	const providerName = "vane-semantics"
	oldProviders := tunnel.RuleProviders()
	oldRules := tunnel.Rules()
	provider := RP.NewRuleSetProvider(providerName, P.Domain, P.YamlRule, 0, nil,
		[]string{"+.example.com"}, nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{providerName: provider})
	defer tunnel.UpdateRules(oldRules, nil, oldProviders)

	cases := []struct {
		host  string
		match bool
		why   string
	}{
		{"example.com", true, "a leading +. covers the apex domain"},
		{"media.example.com", true, "a leading +. covers subdomains"},
		{"deep.media.example.com", true, "subdomains of any depth are covered"},
		{"other.test", false, "an unrelated host never matches"},
		{"example.com.evil.test", false, "the suffix must land on a label boundary"},
		{"notexample.com", false, "a longer label sharing the tail is not a subdomain"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			require.Equal(t, tc.match, provider.Match(&C.Metadata{Host: tc.host}, C.RuleMatchHelper{}),
				"provider domain matching: %s", tc.why)
		})
	}
}

// The same lookalike host must not be gate-eligible through a RULE-SET scene
// rule, because Vane inherits whatever the provider decides.
func TestVaneRuleSetSceneRuleRejectsLookalikeHost(t *testing.T) {
	const providerName = "vane-semantics-gate"
	oldProviders := tunnel.RuleProviders()
	oldRules := tunnel.Rules()
	provider := RP.NewRuleSetProvider(providerName, P.Domain, P.YamlRule, 0, nil,
		[]string{"+.example.com"}, nil, nil)
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{providerName: provider})
	defer tunnel.UpdateRules(oldRules, nil, oldProviders)

	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true))
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.rules = []vaneFamilyRule{{kind: vaneRuleRuleSet, value: providerName}}
	group.media.domains = nil
	group.media.ruleSets = nil
	group.media.geoSites = nil

	require.Equal(t, providerName, group.mediaTargetKey("media.example.com", 443).target,
		"a subdomain inside the provider is gate-eligible with the provider name as scope")
	require.Empty(t, group.mediaTargetKey("example.com.evil.test", 443).target,
		"a lookalike host must not open the gate")
	lookalike := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "example.com.evil.test", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, lookalike, "PHASE1: every TCP flow is watched")
	require.False(t, lookalike.flowMedia, "a lookalike host is not a media flow")
	lookalike.releaseActiveFlowCount()
}
