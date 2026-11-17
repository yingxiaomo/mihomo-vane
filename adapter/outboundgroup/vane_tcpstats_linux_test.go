//go:build linux

package outboundgroup

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// B2 item 1 (Linux acceptance): a real TCP socket must expose its cumulative
// counters via TCP_INFO through the unwrap.
func TestVaneReadTCPStatsLinuxSocket(t *testing.T) {
	tcpConn := vaneLocalTCPConn(t)
	payload := make([]byte, 16*1024)
	_, err := tcpConn.Write(payload)
	require.NoError(t, err)

	stats := vaneReadTCPStats(tcpConn)
	require.NotNil(t, stats, "a real TCP socket supports TCP_INFO")
	rate, ok := stats.lossRate()
	require.True(t, ok, "segments were sent, so the loss ratio is well-defined")
	require.GreaterOrEqual(t, rate, 0.0)
	require.LessOrEqual(t, rate, 1.0)
}
