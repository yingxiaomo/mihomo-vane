package outboundgroup

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// METRIC-CUMUL-02: a node that never sent anything has no loss signal — never
// "zero loss".
func TestVaneNodeCumulativeLossRate(t *testing.T) {
	cases := []struct {
		name      string
		sent      uint64
		retrans   uint64
		wantRate  float64
		wantValid bool
	}{
		{"lossy", 10_000, 800, 0.08, true},
		{"clean", 1_000, 0, 0, true},
		{"never-sent", 0, 0, 0, false},
		{"clamped", 1_000, 5_000, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			state := &vaneNodeState{cumulSent: tc.sent, cumulRetrans: tc.retrans, cumulAt: now}
			rate, ok := state.cumulLossRate(now)
			require.Equal(t, tc.wantValid, ok)
			require.InDelta(t, tc.wantRate, rate, 1e-9)
		})
	}
	var nilState *vaneNodeState
	_, ok := nilState.cumulLossRate(time.Now())
	require.False(t, ok, "a missing node is not a zero-loss node")
}

// PERSIST-CUMUL-01: the B.3 counters survive a reload.
func TestVaneCumulativeLossSurvivesPersist(t *testing.T) {
	now := time.Now()
	var metrics vaneMetrics
	metrics.observeThroughput(now, 8_000_000)

	persisted := vanePersistedNode{
		Name:            "beta",
		Identity:        "test:beta",
		LastSeen:        now,
		TCP:             persistVaneMetrics(metrics, now),
		CumulSent:       10_000,
		CumulRetrans:    800,
		CumulObservedAt: now,
	}
	encoded, err := json.Marshal(persisted)
	require.NoError(t, err)

	var decoded vanePersistedNode
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, uint64(10_000), decoded.CumulSent)
	require.Equal(t, uint64(800), decoded.CumulRetrans)

	state, valid, invalid := restoreVaneNode(decoded, now)
	require.True(t, valid)
	require.False(t, invalid)
	require.NotNil(t, state)
	rate, ok := state.cumulLossRate(now)
	require.True(t, ok, "the cumulative counters must cross the reload")
	require.InDelta(t, 0.08, rate, 1e-9)
}

// METRIC-CUMUL-01 support: the raw counters behind a socket's loss ratio fall
// back to bytes when the kernel reports no segment counts.
func TestVaneTCPStatsLossCounters(t *testing.T) {
	var missing *vaneTCPStats
	sent, retrans := missing.lossCounters()
	require.Zero(t, sent)
	require.Zero(t, retrans)

	segments := &vaneTCPStats{segsOut: 100, retransSegs: 5, bytesSent: 1_000, bytesRetrans: 50}
	sent, retrans = segments.lossCounters()
	require.Equal(t, uint64(100), sent)
	require.Equal(t, uint64(5), retrans)

	bytesOnly := &vaneTCPStats{bytesSent: 1_000, bytesRetrans: 50}
	sent, retrans = bytesOnly.lossCounters()
	require.Equal(t, uint64(1_000), sent)
	require.Equal(t, uint64(50), retrans)
}
