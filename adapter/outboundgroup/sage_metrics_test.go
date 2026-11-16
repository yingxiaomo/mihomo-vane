package outboundgroup

import (
	"math"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

type sageFakeClock struct {
	now time.Time
}

func (c *sageFakeClock) Now() time.Time { return c.now }

func (c *sageFakeClock) Add(elapsed time.Duration) { c.now = c.now.Add(elapsed) }

func TestSageMetricsClassification(t *testing.T) {
	t.Run("CLS-01 parses every supported matcher and all four scenes", func(t *testing.T) {
		tests := []struct {
			name     string
			raw      string
			metadata *C.Metadata
			scene    sageScene
		}{
			{"domain", "DOMAIN,api.example.com,interactive", &C.Metadata{Host: "API.Example.Com"}, sageSceneInteractive},
			{"domain root dot", "DOMAIN,api.example.com.,interactive", &C.Metadata{Host: "API.Example.Com."}, sageSceneInteractive},
			{"sniff domain", "DOMAIN,sniff.example,media", &C.Metadata{Host: "other.example", SniffHost: "sniff.example"}, sageSceneMedia},
			{"domain suffix", "DOMAIN-SUFFIX,example.com,media", &C.Metadata{Host: "video.cdn.EXAMPLE.com"}, sageSceneMedia},
			{"domain suffix root dot", "DOMAIN-SUFFIX,example.com.,media", &C.Metadata{Host: "video.cdn.EXAMPLE.com."}, sageSceneMedia},
			{"network", "NETWORK,udp,bulk", &C.Metadata{NetWork: C.UDP}, sageSceneBulk},
			{"destination port", "DST-PORT,80/443/8000-9000,interactive", &C.Metadata{DstPort: 8443}, sageSceneInteractive},
			{"inbound name", "IN-NAME,lan/mixed,default", &C.Metadata{InName: "mixed"}, sageSceneDefault},
			{"inbound user", "IN-USER,alice/bob,media", &C.Metadata{InUser: "bob"}, sageSceneMedia},
			{"process", "PROCESS,Player.EXE,media", &C.Metadata{Process: "player.exe"}, sageSceneMedia},
			{"process path", `PROCESS-PATH,C:\Apps\Downloader.exe,bulk`, &C.Metadata{ProcessPath: `c:\apps\downloader.EXE`}, sageSceneBulk},
			{"dscp", "DSCP,8/40-46,interactive", &C.Metadata{DSCP: 46}, sageSceneInteractive},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				rules, err := parseSageSceneRules([]string{test.raw})
				require.NoError(t, err)
				require.Equal(t, test.scene, classifySageScene(test.metadata, rules))
			})
		}
	})

	t.Run("CLS-02 first matching rule wins", func(t *testing.T) {
		rules, err := parseSageSceneRules([]string{
			"DOMAIN-SUFFIX,example.com,interactive",
			"DOMAIN,video.example.com,media",
			"NETWORK,tcp,bulk",
		})
		require.NoError(t, err)
		metadata := &C.Metadata{Host: "video.example.com", NetWork: C.TCP}
		require.Equal(t, sageSceneInteractive, classifySageScene(metadata, rules))
	})

	t.Run("CLS-03 nil missing unmatched and invalid fall back", func(t *testing.T) {
		require.Equal(t, sageSceneDefault, classifySageScene(nil, nil))
		require.Equal(t, sageSceneDefault, classifySageScene(&C.Metadata{}, nil))
		require.Equal(t, sageSceneDefault, classifySageScene(&C.Metadata{Host: "other.example"}, []sageSceneRule{{}}))
		missingRules, err := parseSageSceneRules([]string{
			"DST-PORT,0,bulk",
			"DSCP,0,media",
		})
		require.NoError(t, err)
		require.Equal(t, sageSceneDefault, classifySageScene(&C.Metadata{}, missingRules))

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
			_, err := parseSageSceneRules([]string{raw})
			require.Error(t, err, raw)
		}
	})

	t.Run("CLS-04 invalid domain labels never match domain rules", func(t *testing.T) {
		rules, err := parseSageSceneRules([]string{"DOMAIN-SUFFIX,example.com,media"})
		require.NoError(t, err)
		for _, host := range []string{
			"rr..example.com",
			".example.com",
			"example.com..",
			"192.0.2.1",
			"2001:db8::1",
		} {
			require.Equal(t, sageSceneDefault, classifySageScene(&C.Metadata{Host: host}, rules), host)
		}
	})
}

func TestSageMetricsDecayAndValidity(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)

	t.Run("scene names are closed and stable", func(t *testing.T) {
		require.Equal(t, "default", sageSceneDefault.String())
		require.Equal(t, "interactive", sageSceneInteractive.String())
		require.Equal(t, "media", sageSceneMedia.String())
		require.Equal(t, "bulk", sageSceneBulk.String())
		require.Equal(t, "default", sageScene(255).String())
	})

	t.Run("MET-01 one half-life halves weight and sum", func(t *testing.T) {
		var layer sageDecayLayer
		layer.observe(start, 2*time.Minute, 12, 1)
		decayed := layer.decayed(start.Add(2*time.Minute), 2*time.Minute)
		require.InDelta(t, 0.5, decayed.weight, 1e-12)
		require.InDelta(t, 6, decayed.sum, 1e-12)
		require.InDelta(t, 12, decayed.sum/decayed.weight, 1e-12)
	})

	t.Run("MET-02 fast reacts more strongly than slow", func(t *testing.T) {
		var metric sageDualMetric
		metric.observe(sageMetricFailure, start, 0, 1)
		now := start.Add(30 * time.Minute)
		metric.observe(sageMetricFailure, now, 1, 1)

		fast := metric.fast.decayed(now, sageSpec(sageMetricFailure).fastHalfLife)
		slow := metric.slow.decayed(now, sageSpec(sageMetricFailure).slowHalfLife)
		require.Greater(t, fast.sum/fast.weight, slow.sum/slow.weight)
		require.InDelta(t, 1, fast.sum/fast.weight, 0.0001)
		require.InDelta(t, 2.0/3.0, slow.sum/slow.weight, 1e-12)
	})

	t.Run("MET-03 injected clock and rollback use zero interval", func(t *testing.T) {
		clock := &sageFakeClock{now: start}
		bank := newSageMetricBank(clock)
		bank.observeFailure(false)
		originalUpdate := bank.metrics.failure.fast.updatedAt

		clock.now = start.Add(-time.Hour)
		bank.observeFailure(true)
		require.Equal(t, originalUpdate, bank.metrics.failure.fast.updatedAt)
		require.InDelta(t, 2, bank.metrics.failure.fast.weight, 1e-12)
		require.InDelta(t, 0.5, bank.snapshot().failure.value, 1e-12)

		clock.now = start.Add(sageSpec(sageMetricFailure).fastHalfLife)
		snapshot := bank.snapshot()
		require.True(t, snapshot.failure.valid)
		require.Greater(t, snapshot.failure.confidence, 0.0)
	})

	t.Run("MET-04 evidence below threshold is missing", func(t *testing.T) {
		metric := sageDualMetric{
			fast: sageDecayLayer{weight: sageMinimumEvidence / 2, sum: sageMinimumEvidence / 2, valid: true, updatedAt: start},
			slow: sageDecayLayer{weight: sageMinimumEvidence / 2, sum: sageMinimumEvidence / 2, valid: true, updatedAt: start},
		}
		require.False(t, metric.estimate(sageMetricFailure, start).valid)

		metric.fast.weight = sageMinimumEvidence
		metric.fast.sum = sageMinimumEvidence
		estimate := metric.estimate(sageMetricFailure, start)
		require.True(t, estimate.valid)
		require.InDelta(t, 1, estimate.value, 1e-12)
	})

	t.Run("metrics have independent validity", func(t *testing.T) {
		var metrics sageMetrics
		metrics.observeConnect(start, 125*time.Millisecond)
		snapshot := metrics.snapshot(start)
		require.False(t, snapshot.failure.valid)
		require.True(t, snapshot.connect.valid)
		require.False(t, snapshot.response.valid)
		require.False(t, snapshot.throughput.valid)
	})

	t.Run("clock-injected bank records every independent metric", func(t *testing.T) {
		clock := &sageFakeClock{now: start}
		bank := newSageMetricBank(clock)
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
		bank := newSageMetricBank(nil)
		bank.observeFailure(false)
		require.True(t, bank.snapshot().failure.valid)
	})

	t.Run("invalid quality or value does not create evidence", func(t *testing.T) {
		var layer sageDecayLayer
		layer.observe(start, time.Minute, 1, 0)
		layer.observe(start, time.Minute, math.NaN(), 1)
		layer.observe(start, time.Minute, 1, math.Inf(1))
		require.False(t, layer.valid)
	})
}

func TestSageMetricsMissingCosts(t *testing.T) {
	t.Run("MISS-01 all missing is conservative rather than perfect", func(t *testing.T) {
		score := scoreSageMetrics(sageSceneDefault, sageMetricsSnapshot{})
		require.Equal(t, int64(492_500), score)
		require.Greater(t, score, int64(0))
	})

	t.Run("MISS-02 a partial perfect observation leaves missing penalties", func(t *testing.T) {
		snapshot := sageMetricsSnapshot{
			connect: sageMetricEstimate{value: math.Log(1), confidence: 1, valid: true},
		}
		score := scoreSageMetrics(sageSceneDefault, snapshot)
		require.Equal(t, int64(382_500), score)
		require.Greater(t, score, int64(0))
	})
}

func TestSageMetricsSceneScores(t *testing.T) {
	profile := func(connectMS, responseMS, throughputBPS float64) sageMetricsSnapshot {
		return sageMetricsSnapshot{
			failure:    sageMetricEstimate{value: 0, confidence: 1, valid: true},
			connect:    sageMetricEstimate{value: math.Log(connectMS), confidence: 1, valid: true},
			response:   sageMetricEstimate{value: math.Log(responseMS), confidence: 1, valid: true},
			throughput: sageMetricEstimate{value: math.Log(throughputBPS), confidence: 1, valid: true},
		}
	}

	// These exact same node profiles are ranked under every scene.
	nodes := map[string]sageMetricsSnapshot{
		"interactive-node": profile(50, 100, 250_000),
		"media-node":       profile(200, 300, 12_000_000),
		"bulk-node":        profile(500, 1000, 80_000_000),
	}

	t.Run("SCORE-01 interactive prioritizes setup and response", func(t *testing.T) {
		ranked := rankSageCandidates(sageSceneInteractive, nodes)
		require.Equal(t, "interactive-node", ranked[0].name)
	})
	t.Run("SCORE-02 media rewards adequate throughput without bulk latency", func(t *testing.T) {
		ranked := rankSageCandidates(sageSceneMedia, nodes)
		require.Equal(t, "media-node", ranked[0].name)
	})
	t.Run("SCORE-03 bulk prioritizes sustained throughput", func(t *testing.T) {
		ranked := rankSageCandidates(sageSceneBulk, nodes)
		require.Equal(t, "bulk-node", ranked[0].name)
	})
}

func TestSageMetricsDeterminism(t *testing.T) {
	profile := sageMetricsSnapshot{
		failure:    sageMetricEstimate{value: 0.2, confidence: 0.75, valid: true},
		connect:    sageMetricEstimate{value: math.Log(200), confidence: 0.6, valid: true},
		response:   sageMetricEstimate{value: math.Log(500), confidence: 0.5, valid: true},
		throughput: sageMetricEstimate{value: math.Log(8_000_000), confidence: 0.8, valid: true},
	}

	t.Run("DEC-01 identical input is stable for 1000 decisions", func(t *testing.T) {
		var expected []sageCandidateScore
		for i := 0; i < 1000; i++ {
			candidates := map[string]sageMetricsSnapshot{
				"node-c": profile,
				"node-a": profile,
				"node-b": profile,
			}
			ranked := rankSageCandidates(sageSceneDefault, candidates)
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
			candidates := make(map[string]sageMetricsSnapshot, len(names))
			for i := range names {
				name := names[(i+offset)%len(names)]
				candidates[name] = profile
			}
			ranked := rankSageCandidates(sageSceneDefault, candidates)
			require.Equal(t, []string{"node-a", "node-b", "node-c", "node-d"}, candidateNames(ranked))
		}
	})

	t.Run("DEC-03 equal quantized scores use UTF-8 name order", func(t *testing.T) {
		ranked := rankSageCandidates(sageSceneDefault, map[string]sageMetricsSnapshot{
			"节点":     profile,
			"éclair": profile,
			"alpha":  profile,
		})
		require.Equal(t, []string{"alpha", "éclair", "节点"}, candidateNames(ranked))
		require.Less(t, compareSageCandidateScores(ranked[0], ranked[1]), 0)
	})
}

func candidateNames(ranked []sageCandidateScore) []string {
	names := make([]string, len(ranked))
	for i, candidate := range ranked {
		names[i] = candidate.name
	}
	return names
}
