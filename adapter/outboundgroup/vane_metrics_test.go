package outboundgroup

import (
	"math"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/require"
)

type vaneFakeClock struct {
	now time.Time
}

func (c *vaneFakeClock) Now() time.Time { return c.now }

func (c *vaneFakeClock) Add(elapsed time.Duration) { c.now = c.now.Add(elapsed) }

func TestVaneMetricsClassification(t *testing.T) {
	t.Run("CLS-01 parses every supported matcher and all four scenes", func(t *testing.T) {
		tests := []struct {
			name     string
			raw      string
			metadata *C.Metadata
			scene    vaneScene
		}{
			{"domain", "DOMAIN,api.example.com,interactive", &C.Metadata{Host: "API.Example.Com"}, vaneSceneInteractive},
			{"domain root dot", "DOMAIN,api.example.com.,interactive", &C.Metadata{Host: "API.Example.Com."}, vaneSceneInteractive},
			{"sniff domain", "DOMAIN,sniff.example,media", &C.Metadata{Host: "other.example", SniffHost: "sniff.example"}, vaneSceneMedia},
			{"domain suffix", "DOMAIN-SUFFIX,example.com,media", &C.Metadata{Host: "video.cdn.EXAMPLE.com"}, vaneSceneMedia},
			{"domain suffix root dot", "DOMAIN-SUFFIX,example.com.,media", &C.Metadata{Host: "video.cdn.EXAMPLE.com."}, vaneSceneMedia},
			{"network", "NETWORK,udp,bulk", &C.Metadata{NetWork: C.UDP}, vaneSceneBulk},
			{"destination port", "DST-PORT,80/443/8000-9000,interactive", &C.Metadata{DstPort: 8443}, vaneSceneInteractive},
			{"inbound name", "IN-NAME,lan/mixed,default", &C.Metadata{InName: "mixed"}, vaneSceneDefault},
			{"inbound user", "IN-USER,alice/bob,media", &C.Metadata{InUser: "bob"}, vaneSceneMedia},
			{"process", "PROCESS,Player.EXE,media", &C.Metadata{Process: "player.exe"}, vaneSceneMedia},
			{"process path", `PROCESS-PATH,C:\Apps\Downloader.exe,bulk`, &C.Metadata{ProcessPath: `c:\apps\downloader.EXE`}, vaneSceneBulk},
			{"dscp", "DSCP,8/40-46,interactive", &C.Metadata{DSCP: 46}, vaneSceneInteractive},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				rules, err := parseVaneSceneRules([]string{test.raw})
				require.NoError(t, err)
				require.Equal(t, test.scene, classifyVaneScene(test.metadata, rules))
			})
		}
	})

	t.Run("CLS-02 first matching rule wins", func(t *testing.T) {
		rules, err := parseVaneSceneRules([]string{
			"DOMAIN-SUFFIX,example.com,interactive",
			"DOMAIN,video.example.com,media",
			"NETWORK,tcp,bulk",
		})
		require.NoError(t, err)
		metadata := &C.Metadata{Host: "video.example.com", NetWork: C.TCP}
		require.Equal(t, vaneSceneInteractive, classifyVaneScene(metadata, rules))
	})

	t.Run("CLS-03 nil missing unmatched and invalid fall back", func(t *testing.T) {
		require.Equal(t, vaneSceneDefault, classifyVaneScene(nil, nil))
		require.Equal(t, vaneSceneDefault, classifyVaneScene(&C.Metadata{}, nil))
		require.Equal(t, vaneSceneDefault, classifyVaneScene(&C.Metadata{Host: "other.example"}, []vaneSceneRule{{}}))
		missingRules, err := parseVaneSceneRules([]string{
			"DST-PORT,0,bulk",
			"DSCP,0,media",
		})
		require.NoError(t, err)
		require.Equal(t, vaneSceneDefault, classifyVaneScene(&C.Metadata{}, missingRules))

		invalid := []string{
			"DOMAIN,example.com,unknown",
			"DOMAIN,..,media",
			"DOMAIN,.example.com,media",
			"DOMAIN,example..com,media",
			"DOMAIN,example.com..,media",
			"DOMAIN-SUFFIX,..,media",
			"DOMAIN-SUFFIX,.example.com,media",
			"DOMAIN-SUFFIX,example..com,media",
			"DOMAIN-SUFFIX,example.com..,media",
			"NETWORK,icmp,media",
			"DST-PORT,70000,media",
			"DSCP,64,media",
			"PROCESS,,media",
			"UNKNOWN,value,media",
			"DOMAIN,missing-scene",
		}
		for _, raw := range invalid {
			_, err := parseVaneSceneRules([]string{raw})
			require.Error(t, err, raw)
		}
	})

	t.Run("CLS-04 invalid domain labels never match domain rules", func(t *testing.T) {
		rules, err := parseVaneSceneRules([]string{"DOMAIN-SUFFIX,example.com,media"})
		require.NoError(t, err)
		for _, host := range []string{
			"rr..example.com",
			".example.com",
			"example.com..",
			"192.0.2.1",
			"2001:db8::1",
		} {
			require.Equal(t, vaneSceneDefault, classifyVaneScene(&C.Metadata{Host: host}, rules), host)
		}
	})
}

func TestVaneMetricsDecayAndValidity(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)

	t.Run("scene names are closed and stable", func(t *testing.T) {
		require.Equal(t, "default", vaneSceneDefault.String())
		require.Equal(t, "interactive", vaneSceneInteractive.String())
		require.Equal(t, "media", vaneSceneMedia.String())
		require.Equal(t, "bulk", vaneSceneBulk.String())
		require.Equal(t, "default", vaneScene(255).String())
	})

	t.Run("MET-01 one half-life halves weight and sum", func(t *testing.T) {
		var layer vaneDecayLayer
		layer.observe(start, 2*time.Minute, 12, 1)
		decayed := layer.decayed(start.Add(2*time.Minute), 2*time.Minute)
		require.InDelta(t, 0.5, decayed.weight, 1e-12)
		require.InDelta(t, 6, decayed.sum, 1e-12)
		require.InDelta(t, 12, decayed.sum/decayed.weight, 1e-12)
	})

	t.Run("MET-02 fast reacts more strongly than slow", func(t *testing.T) {
		var metric vaneDualMetric
		metric.observe(vaneMetricFailure, start, 0, 1)
		now := start.Add(30 * time.Minute)
		metric.observe(vaneMetricFailure, now, 1, 1)

		fast := metric.fast.decayed(now, vaneSpec(vaneMetricFailure).fastHalfLife)
		slow := metric.slow.decayed(now, vaneSpec(vaneMetricFailure).slowHalfLife)
		require.Greater(t, fast.sum/fast.weight, slow.sum/slow.weight)
		require.InDelta(t, 1, fast.sum/fast.weight, 0.0001)
		require.InDelta(t, 2.0/3.0, slow.sum/slow.weight, 1e-12)
	})

	t.Run("MET-03 injected clock and rollback use zero interval", func(t *testing.T) {
		clock := &vaneFakeClock{now: start}
		bank := newVaneMetricBank(clock)
		bank.observeFailure(false)
		originalUpdate := bank.metrics.failure.fast.updatedAt

		clock.now = start.Add(-time.Hour)
		bank.observeFailure(true)
		require.Equal(t, originalUpdate, bank.metrics.failure.fast.updatedAt)
		require.InDelta(t, 2, bank.metrics.failure.fast.weight, 1e-12)
		require.InDelta(t, 0.5, bank.snapshot().failure.value, 1e-12)

		clock.now = start.Add(vaneSpec(vaneMetricFailure).fastHalfLife)
		snapshot := bank.snapshot()
		require.True(t, snapshot.failure.valid)
		require.Greater(t, snapshot.failure.confidence, 0.0)
	})

	t.Run("MET-04 evidence below threshold is missing", func(t *testing.T) {
		metric := vaneDualMetric{
			fast: vaneDecayLayer{weight: vaneMinimumEvidence / 2, sum: vaneMinimumEvidence / 2, valid: true, updatedAt: start},
			slow: vaneDecayLayer{weight: vaneMinimumEvidence / 2, sum: vaneMinimumEvidence / 2, valid: true, updatedAt: start},
		}
		require.False(t, metric.estimate(vaneMetricFailure, start).valid)

		metric.fast.weight = vaneMinimumEvidence
		metric.fast.sum = vaneMinimumEvidence
		estimate := metric.estimate(vaneMetricFailure, start)
		require.True(t, estimate.valid)
		require.InDelta(t, 1, estimate.value, 1e-12)
	})

	t.Run("metrics have independent validity", func(t *testing.T) {
		var metrics vaneMetrics
		metrics.observeConnect(start, 125*time.Millisecond)
		snapshot := metrics.snapshot(start)
		require.False(t, snapshot.failure.valid)
		require.True(t, snapshot.connect.valid)
		require.False(t, snapshot.response.valid)
		require.False(t, snapshot.throughput.valid)
	})

	t.Run("clock-injected bank records every independent metric", func(t *testing.T) {
		clock := &vaneFakeClock{now: start}
		bank := newVaneMetricBank(clock)
		bank.observeConnect(40 * time.Millisecond)
		bank.observeResponse(90 * time.Millisecond)
		bank.observeThroughput(20_000_000)
		snapshot := bank.snapshot()
		require.True(t, snapshot.connect.valid)
		require.True(t, snapshot.response.valid)
		require.True(t, snapshot.throughput.valid)
		require.InDelta(t, math.Log(40), snapshot.connect.value, 1e-12)
		require.InDelta(t, math.Log(90), snapshot.response.value, 1e-12)
		require.InDelta(t, math.Log(20_000_000), snapshot.throughput.value, 1e-12)
	})

	t.Run("nil clock gets a working system clock", func(t *testing.T) {
		bank := newVaneMetricBank(nil)
		bank.observeFailure(false)
		require.True(t, bank.snapshot().failure.valid)
	})

	t.Run("invalid quality or value does not create evidence", func(t *testing.T) {
		var layer vaneDecayLayer
		layer.observe(start, time.Minute, 1, 0)
		layer.observe(start, time.Minute, math.NaN(), 1)
		layer.observe(start, time.Minute, 1, math.Inf(1))
		require.False(t, layer.valid)
	})
}

func TestVaneMetricsMissingCosts(t *testing.T) {
	t.Run("MISS-01 all missing is conservative rather than perfect", func(t *testing.T) {
		score := scoreVaneMetrics(vaneSceneDefault, vaneMetricsSnapshot{})
		require.Equal(t, int64(492_500), score)
		require.Greater(t, score, int64(0))
	})

	t.Run("MISS-02 a partial perfect observation leaves missing penalties", func(t *testing.T) {
		snapshot := vaneMetricsSnapshot{
			connect: vaneMetricEstimate{value: math.Log(1), confidence: 1, valid: true},
		}
		score := scoreVaneMetrics(vaneSceneDefault, snapshot)
		require.Equal(t, int64(382_500), score)
		require.Greater(t, score, int64(0))
	})
}

func TestVaneMetricsSceneScores(t *testing.T) {
	profile := func(connectMS, responseMS, throughputBPS float64) vaneMetricsSnapshot {
		return vaneMetricsSnapshot{
			failure:    vaneMetricEstimate{value: 0, confidence: 1, valid: true},
			connect:    vaneMetricEstimate{value: math.Log(connectMS), confidence: 1, valid: true},
			response:   vaneMetricEstimate{value: math.Log(responseMS), confidence: 1, valid: true},
			throughput: vaneMetricEstimate{value: math.Log(throughputBPS), confidence: 1, valid: true},
		}
	}

	// These exact same node profiles are ranked under every scene.
	nodes := map[string]vaneMetricsSnapshot{
		"interactive-node": profile(50, 100, 250_000),
		"media-node":       profile(200, 300, 12_000_000),
		"bulk-node":        profile(500, 1000, 80_000_000),
	}

	t.Run("SCORE-01 interactive prioritizes setup and response", func(t *testing.T) {
		ranked := rankVaneCandidates(vaneSceneInteractive, nodes)
		require.Equal(t, "interactive-node", ranked[0].name)
	})
	t.Run("SCORE-02 media rewards adequate throughput without bulk latency", func(t *testing.T) {
		ranked := rankVaneCandidates(vaneSceneMedia, nodes)
		require.Equal(t, "media-node", ranked[0].name)
	})
	t.Run("SCORE-03 bulk prioritizes sustained throughput", func(t *testing.T) {
		ranked := rankVaneCandidates(vaneSceneBulk, nodes)
		require.Equal(t, "bulk-node", ranked[0].name)
	})
}

func TestVaneMetricsDeterminism(t *testing.T) {
	profile := vaneMetricsSnapshot{
		failure:    vaneMetricEstimate{value: 0.2, confidence: 0.75, valid: true},
		connect:    vaneMetricEstimate{value: math.Log(200), confidence: 0.6, valid: true},
		response:   vaneMetricEstimate{value: math.Log(500), confidence: 0.5, valid: true},
		throughput: vaneMetricEstimate{value: math.Log(8_000_000), confidence: 0.8, valid: true},
	}

	t.Run("DEC-01 identical input is stable for 1000 decisions", func(t *testing.T) {
		var expected []vaneCandidateScore
		for i := 0; i < 1000; i++ {
			candidates := map[string]vaneMetricsSnapshot{
				"node-c": profile,
				"node-a": profile,
				"node-b": profile,
			}
			ranked := rankVaneCandidates(vaneSceneDefault, candidates)
			if i == 0 {
				expected = ranked
			} else {
				require.Equal(t, expected, ranked)
			}
		}
	})

	t.Run("DEC-02 map insertion order cannot affect rank", func(t *testing.T) {
		names := []string{"node-d", "node-c", "node-b", "node-a"}
		for offset := 0; offset < len(names); offset++ {
			candidates := make(map[string]vaneMetricsSnapshot, len(names))
			for i := range names {
				name := names[(i+offset)%len(names)]
				candidates[name] = profile
			}
			ranked := rankVaneCandidates(vaneSceneDefault, candidates)
			require.Equal(t, []string{"node-a", "node-b", "node-c", "node-d"}, candidateNames(ranked))
		}
	})

	t.Run("DEC-03 equal quantized scores use UTF-8 name order", func(t *testing.T) {
		ranked := rankVaneCandidates(vaneSceneDefault, map[string]vaneMetricsSnapshot{
			"节点":     profile,
			"éclair": profile,
			"alpha":  profile,
		})
		require.Equal(t, []string{"alpha", "éclair", "节点"}, candidateNames(ranked))
		require.Less(t, compareVaneCandidateScores(ranked[0], ranked[1]), 0)
	})
}

func candidateNames(ranked []vaneCandidateScore) []string {
	names := make([]string, len(ranked))
	for i, candidate := range ranked {
		names[i] = candidate.name
	}
	return names
}

// RULESET-SCENE-001: scene rules accept RULE-SET. The provider name is stored
// verbatim at parse time and resolved against the tunnel registry on every
// match — registration, updates and removals are all reflected, an
// unregistered provider is "no match", never an error.
func TestVaneSceneRuleSet(t *testing.T) {
	rule, err := parseVaneSceneRule("RULE-SET,streaming,media")
	require.NoError(t, err)
	require.Equal(t, vaneRuleRuleSet, rule.kind)
	require.Equal(t, "streaming", rule.value)
	_, err = parseVaneSceneRule("RULE-SET,,media")
	require.Error(t, err, "empty payload is rejected by the shared check")

	metadata := &C.Metadata{Host: "media.streaming-provider.test"}
	outside := &C.Metadata{Host: "example.test"}

	t.Run("registered provider matches", func(t *testing.T) {
		oldProviders := tunnel.RuleProviders()
		oldRules := tunnel.Rules()
		provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
			[]string{"+.streaming-provider.test"}, nil, nil)
		tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
		defer tunnel.UpdateRules(oldRules, nil, oldProviders)

		require.Equal(t, vaneSceneMedia, classifyVaneScene(metadata, []vaneSceneRule{rule}),
			"a host inside the provider is classified")
		require.Equal(t, vaneSceneDefault, classifyVaneScene(outside, []vaneSceneRule{rule}),
			"a host outside the provider is not classified")
		require.Equal(t, vaneSceneDefault, classifyVaneScene(metadata, []vaneSceneRule{
			{kind: vaneRuleRuleSet, value: "missing", scene: vaneSceneMedia},
		}), "an unregistered provider never matches and never errors")
	})

	t.Run("first hit wins when mixed with DOMAIN rules", func(t *testing.T) {
		oldProviders := tunnel.RuleProviders()
		oldRules := tunnel.Rules()
		provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
			[]string{"+.streaming-provider.test"}, nil, nil)
		tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
		defer tunnel.UpdateRules(oldRules, nil, oldProviders)

		domainFirst := []vaneSceneRule{
			{kind: vaneRuleDomain, value: "media.streaming-provider.test", scene: vaneSceneInteractive},
			rule,
		}
		require.Equal(t, vaneSceneInteractive, classifyVaneScene(metadata, domainFirst))
		rulesetFirst := []vaneSceneRule{
			rule,
			{kind: vaneRuleDomain, value: "media.streaming-provider.test", scene: vaneSceneInteractive},
		}
		require.Equal(t, vaneSceneMedia, classifyVaneScene(metadata, rulesetFirst))
	})
}

// GEOSITE-SCENE-001: scene rules accept GEOSITE categories. Parsing stores
// the category verbatim (`!` negation and `@attr` are the loader's syntax);
// matching is fail-closed — without a GeoSite database the load errors and
// the rule never matches, with no error and no panic.
func TestVaneSceneGeoSite(t *testing.T) {
	rule, err := parseVaneSceneRule("GEOSITE,category-openai,media")
	require.NoError(t, err)
	require.Equal(t, vaneRuleGeoSite, rule.kind)
	require.Equal(t, "category-openai", rule.value)
	_, err = parseVaneSceneRule("GEOSITE,,media")
	require.Error(t, err, "empty category is rejected by the shared check")

	metadata := &C.Metadata{Host: "api.openai.com"}
	matcher, err := geodata.LoadGeoSiteMatcher("category-openai")
	require.Error(t, err, "the sandbox has no GeoSite database")
	require.Nil(t, matcher)

	require.Equal(t, vaneSceneDefault, classifyVaneScene(metadata, []vaneSceneRule{rule}),
		"fail-closed: no database means the rule never matches, quietly")
	require.Equal(t, vaneSceneDefault, classifyVaneScene(&C.Metadata{}, []vaneSceneRule{rule}),
		"an empty host never matches")
}
