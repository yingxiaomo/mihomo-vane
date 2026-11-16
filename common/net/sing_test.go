package net

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type relayLifecycleTestConn struct {
	net.Conn
	started  int
	finished int
}

func (c *relayLifecycleTestConn) RelayStarted()  { c.started++ }
func (c *relayLifecycleTestConn) RelayFinished() { c.finished++ }

func TestRelayLifecycleObserverBracketsBothCopyDirections(t *testing.T) {
	leftRelay, leftPeer := net.Pipe()
	rightRelay, rightPeer := net.Pipe()
	left := &relayLifecycleTestConn{Conn: leftRelay}
	right := &relayLifecycleTestConn{Conn: rightRelay}
	done := make(chan struct{})
	go func() {
		Relay(left, right)
		close(done)
	}()

	require.NoError(t, leftPeer.Close())
	require.NoError(t, rightPeer.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay did not stop after both peers closed")
	}

	require.Equal(t, 1, left.started)
	require.Equal(t, 1, left.finished)
	require.Equal(t, 1, right.started)
	require.Equal(t, 1, right.finished)
}
