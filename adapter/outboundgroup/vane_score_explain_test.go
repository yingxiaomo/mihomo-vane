package outboundgroup

import (
	"context"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// SCORE-EXPLAIN-01: the breakdown must add up to the ranking score, and every
// dimension must show up in the log line — that is the whole point of the
// feature, so a missing term is a bug, not cosmetics.
func TestVaneScorePartsExplain(t *testing.T) {
	snapshot := vaneMetricsSnapshot{
		throughput: vaneMetricEstimate{value: 12_000_000, confidence: 1, valid: true},
		latency:    vaneMetricEstimate{value: 280, confidence: 0.5, valid: true},
		loss:       vaneMetricEstimate{value: 0.03, confidence: 0.5, valid: true},
		connect:    vaneMetricEstimate{value: 90, confidence: 1, valid: true},
		response:   vaneMetricEstimate{value: 400, confidence: 1, valid: true},
		failure:    vaneMetricEstimate{value: 0.2, confidence: 1, valid: true},
		success:    vaneMetricEstimate{value: 0.8, confidence: 1, valid: true},
		maxRate:    vaneMetricEstimate{value: 20_000_000, confidence: 1, valid: true},
		duration:   vaneMetricEstimate{value: 60, confidence: 1, valid: true},
	}
	{
		parts := scoreVaneMetricsPartsWith(vaneScoringFlat(), snapshot)
		require.Equal(t, scoreVaneMetricsFlat(snapshot), parts.total)
		sum := parts.throughput + parts.latency + parts.loss + parts.failure +
			parts.response + parts.jitter + parts.connect + parts.success +
			parts.maxRate + parts.duration + parts.downloadTotal
		require.InDelta(t, float64(parts.total)/1_000_000, sum, 1e-6)
	}
	line := scoreVaneMetricsPartsWith(vaneScoringFlat(), snapshot).explain()
	for _, key := range []string{"tp=", "rtt=", "loss=", "fail=", "resp=", "jit=", "conn=", "succ=", "peak=", "dur=", "vol="} {
		require.Contains(t, line, key)
	}
}

// SCORE-EXPLAIN-02: the emitted line carries the winner, its score, the raw
// best score and the contributions, in the fixed field order.
func TestVanePickScoredLogLine(t *testing.T) {
	line := vaneLogLine(vaneDiagnosticRecord{
		kind: "pick-scored", target: "rr1---sn-x.googlevideo.com", port: 443,
		to: "node-a", scene: "media", transport: "tcp",
		scoreMicros: 712345, bestMicros: 800000,
		scoreParts: "tp=0.24 rtt=0.18 loss=0.00 fail=0.00 resp=0.03 jit=0.01 conn=0.02 succ=0.03 peak=0.02 dur=0.01 vol=0.01",
	})
	for _, want := range []string{
		"kind=pick-scored", "to=node-a", "score=0.7123", "best=0.8000",
		"parts=tp=0.24", "vol=0.01",
	} {
		require.Contains(t, line, want)
	}
	require.True(t, strings.HasPrefix(line, "[vane] kind=pick-scored "))
}

// SCORE-EXPLAIN-03: a committed pick reports itself once, and a repeat pick
// that keeps the same anchor stays quiet so browsing does not flood the log.
func TestVanePickScoredRecorded(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	var got []vaneDiagnosticRecord
	group.diagnostics.sink = func(record vaneDiagnosticRecord) {
		got = append(got, record)
	}
	metadata := &C.Metadata{Host: "rr1---sn-x.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())
	require.Len(t, got, 1)
	require.Equal(t, "pick-scored", got[0].kind)
	require.Equal(t, "alpha", got[0].to)
	require.Greater(t, got[0].scoreMicros, int64(0))
	require.Contains(t, got[0].scoreParts, "tp=")

	group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Len(t, got, 1, "an unchanged untargeted anchor must not re-log")
}

// SCORE-EXPLAIN-04: the sticky early returns (target/hint) never reach
// the ranking loop, so they report through the snapshot helper instead.
func TestVanePickScoredSnapshotRecord(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	var got []vaneDiagnosticRecord
	group.diagnostics.sink = func(record vaneDiagnosticRecord) {
		got = append(got, record)
	}
	snapshot := vaneMetricsSnapshot{
		throughput: vaneMetricEstimate{value: 12_000_000, confidence: 1, valid: true},
	}

	group.recordPickScoredSnapshot("hint", vaneTransportTCP, "rr1---sn-x.googlevideo.com", 443, "alpha", snapshot)
	require.Len(t, got, 1)
	require.Equal(t, "pick-scored", got[0].kind)
	require.Equal(t, "hint", got[0].reason)
	require.Equal(t, "alpha", got[0].to)
	require.Greater(t, got[0].scoreMicros, int64(0))
	require.Contains(t, got[0].scoreParts, "tp=")
}
