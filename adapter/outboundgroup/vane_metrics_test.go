package outboundgroup

import (
	"math"
	"sort"
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

// vaneFamilyMatches reports whether any family rule claims the metadata.
func vaneFamilyMatches(metadata *C.Metadata, rules []vaneFamilyRule) bool {
	_, ok := matchVaneFamilyRule(metadata, rules)
	return ok
}

func (c *vaneFakeClock) Now() time.Time { return c.now }

func (c *vaneFakeClock) Add(elapsed time.Duration) { c.now = c.now.Add(elapsed) }

func TestVaneMetricsDecayAndValidity(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)

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
		score := scoreVaneMetricsFlat(vaneMetricsSnapshot{})
		// Eleven dimensions: latency and the five profile dimensions sit at their
		// 0.5 neutral, so the whole table still reads "unknown = mediocre".
		require.Equal(t, int64(549_500), score)
		require.Greater(t, score, int64(0))
	})

	t.Run("MISS-02 a partial perfect observation leaves missing penalties", func(t *testing.T) {
		snapshot := vaneMetricsSnapshot{
			connect: vaneMetricEstimate{value: math.Log(1), confidence: 1, valid: true},
		}
		score := scoreVaneMetricsFlat(snapshot)
		require.Equal(t, int64(538_500), score)
		require.Greater(t, score, int64(0))
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
			ranked := rankVaneCandidates(candidates)
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
			ranked := rankVaneCandidates(candidates)
			require.Equal(t, []string{"node-a", "node-b", "node-c", "node-d"}, candidateNames(ranked))
		}
	})

	t.Run("DEC-03 equal quantized scores use UTF-8 name order", func(t *testing.T) {
		ranked := rankVaneCandidates(map[string]vaneMetricsSnapshot{
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
	rule, err := parseVaneFamilyRule("RULE-SET,streaming")
	require.NoError(t, err)
	require.Equal(t, vaneRuleRuleSet, rule.kind)
	require.Equal(t, "streaming", rule.value)
	_, err = parseVaneFamilyRule("RULE-SET,,media")
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

		require.True(t, vaneFamilyMatches(metadata, []vaneFamilyRule{rule}),
			"a host inside the provider is classified")
		require.False(t, vaneFamilyMatches(outside, []vaneFamilyRule{rule}),
			"a host outside the provider is not classified")
		require.False(t, vaneFamilyMatches(metadata, []vaneFamilyRule{
			{kind: vaneRuleRuleSet, value: "missing"},
		}), "an unregistered provider never matches and never errors")
	})

	t.Run("first hit wins when mixed with DOMAIN rules", func(t *testing.T) {
		oldProviders := tunnel.RuleProviders()
		oldRules := tunnel.Rules()
		provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
			[]string{"+.streaming-provider.test"}, nil, nil)
		tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
		defer tunnel.UpdateRules(oldRules, nil, oldProviders)

		domainFirst := []vaneFamilyRule{
			{kind: vaneRuleDomain, value: "media.streaming-provider.test"},
			rule,
		}
		require.True(t, vaneFamilyMatches(metadata, domainFirst))
		rulesetFirst := []vaneFamilyRule{
			rule,
			{kind: vaneRuleDomain, value: "media.streaming-provider.test"},
		}
		require.True(t, vaneFamilyMatches(metadata, rulesetFirst))
	})
}

// GEOSITE-SCENE-001: scene rules accept GEOSITE categories. Parsing stores
// the category verbatim (`!` negation and `@attr` are the loader's syntax);
// matching is fail-closed — without a GeoSite database the load errors and
// the rule never matches, with no error and no panic.
func TestVaneSceneGeoSite(t *testing.T) {
	rule, err := parseVaneFamilyRule("GEOSITE,category-openai")
	require.NoError(t, err)
	require.Equal(t, vaneRuleGeoSite, rule.kind)
	require.Equal(t, "category-openai", rule.value)
	_, err = parseVaneFamilyRule("GEOSITE,,media")
	require.Error(t, err, "empty category is rejected by the shared check")

	metadata := &C.Metadata{Host: "api.openai.com"}
	matcher, err := geodata.LoadGeoSiteMatcher("category-openai")
	require.Error(t, err, "the sandbox has no GeoSite database")
	require.Nil(t, matcher)

	require.False(t, vaneFamilyMatches(metadata, []vaneFamilyRule{rule}),
		"fail-closed: no database means the rule never matches, quietly")
	require.False(t, vaneFamilyMatches(&C.Metadata{}, []vaneFamilyRule{rule}),
		"an empty host never matches")
}

// vaneMetricBank is a small clock-injected convenience for event writers.
// Selection can copy metrics and call snapshot with one shared timestamp.
// TEST-WRAP-001: test-only, moved out of vane_metrics.go.
type vaneMetricBank struct {
	clock   vaneClock
	metrics vaneMetrics
}

func newVaneMetricBank(clock vaneClock) *vaneMetricBank {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	return &vaneMetricBank{clock: clock}
}

func (b *vaneMetricBank) observeFailure(failed bool) {
	b.metrics.observeFailure(b.clock.Now(), failed)
}

func (b *vaneMetricBank) observeConnect(elapsed time.Duration) {
	b.metrics.observeConnect(b.clock.Now(), elapsed)
}

func (b *vaneMetricBank) observeResponse(elapsed time.Duration) {
	b.metrics.observeResponse(b.clock.Now(), elapsed)
}

func (b *vaneMetricBank) observeThroughput(bitsPerSecond float64) {
	b.metrics.observeThroughput(b.clock.Now(), bitsPerSecond)
}

func (b *vaneMetricBank) snapshot() vaneMetricsSnapshot {
	return b.metrics.snapshot(b.clock.Now())
}

// TEST-WRAP-001: test-only, moved out of vane_metrics.go.
func rankVaneCandidates(snapshots map[string]vaneMetricsSnapshot) []vaneCandidateScore {
	ranked := make([]vaneCandidateScore, 0, len(snapshots))
	for name, snapshot := range snapshots {
		ranked = append(ranked, vaneCandidateScore{name: name, scoreMicros: scoreVaneMetricsFlat(snapshot)})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return compareVaneCandidateScores(ranked[i], ranked[j]) < 0
	})
	return ranked
}
