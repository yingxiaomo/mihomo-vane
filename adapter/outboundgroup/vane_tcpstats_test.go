package outboundgroup

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type vaneTCPU_wrapper struct {
	net.Conn
}

func (c *vaneTCPU_wrapper) Upstream() net.Conn { return c.Conn }

type vaneTCPC_wrapper struct {
	net.Conn
}

func (c *vaneTCPC_wrapper) NetConn() net.Conn { return c.Conn }

type vaneTCPSecret_wrapper struct {
	hidden net.Conn
}

func (c *vaneTCPSecret_wrapper) Read(b []byte) (int, error)       { return c.hidden.Read(b) }
func (c *vaneTCPSecret_wrapper) Write(b []byte) (int, error)      { return c.hidden.Write(b) }
func (c *vaneTCPSecret_wrapper) Close() error                     { return c.hidden.Close() }
func (c *vaneTCPSecret_wrapper) LocalAddr() net.Addr              { return c.hidden.LocalAddr() }
func (c *vaneTCPSecret_wrapper) RemoteAddr() net.Addr             { return c.hidden.RemoteAddr() }
func (c *vaneTCPSecret_wrapper) SetDeadline(time.Time) error      { return nil }
func (c *vaneTCPSecret_wrapper) SetReadDeadline(time.Time) error  { return nil }
func (c *vaneTCPSecret_wrapper) SetWriteDeadline(time.Time) error { return nil }

// vaneTCPDoubleConn hides two connection-shaped fields: the unwrap must refuse
// to guess instead of inspecting the wrong socket.
type vaneTCPDoubleConn struct {
	left  net.Conn
	right net.Conn
}

func (c *vaneTCPDoubleConn) Read(b []byte) (int, error)       { return c.left.Read(b) }
func (c *vaneTCPDoubleConn) Write(b []byte) (int, error)      { return c.left.Write(b) }
func (c *vaneTCPDoubleConn) Close() error                     { return c.left.Close() }
func (c *vaneTCPDoubleConn) LocalAddr() net.Addr              { return c.left.LocalAddr() }
func (c *vaneTCPDoubleConn) RemoteAddr() net.Addr             { return c.left.RemoteAddr() }
func (c *vaneTCPDoubleConn) SetDeadline(time.Time) error      { return nil }
func (c *vaneTCPDoubleConn) SetReadDeadline(time.Time) error  { return nil }
func (c *vaneTCPDoubleConn) SetWriteDeadline(time.Time) error { return nil }

// vaneTCPCycleConn returns itself from Upstream: the walk must cut the loop.
type vaneTCPCycleConn struct {
	net.Conn
}

func (c *vaneTCPCycleConn) Upstream() net.Conn { return c }

func vaneLocalTCPConn(t *testing.T) *net.TCPConn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	server := <-accepted
	t.Cleanup(func() { server.Close() })
	tcpConn, ok := client.(*net.TCPConn)
	require.True(t, ok)
	return tcpConn
}

// B2 item 1: the wrapper walk resolves known wrappers, reflected fields and
// TLS, and refuses ambiguous or cyclic chains (nil = unsupported).
func TestVaneUnwrapTCPConn(t *testing.T) {
	tcpConn := vaneLocalTCPConn(t)

	t.Run("direct tcp conn", func(t *testing.T) {
		require.Same(t, tcpConn, vaneUnwrapTCPConn(tcpConn))
	})

	t.Run("upstream wrapper", func(t *testing.T) {
		require.Same(t, tcpConn, vaneUnwrapTCPConn(&vaneTCPU_wrapper{Conn: tcpConn}))
	})

	t.Run("tls conn", func(t *testing.T) {
		tlsConn := tls.Client(tcpConn, &tls.Config{InsecureSkipVerify: true})
		require.Same(t, tcpConn, vaneUnwrapTCPConn(tlsConn))
	})

	t.Run("upstream then netconn chain", func(t *testing.T) {
		chained := &vaneTCPU_wrapper{Conn: &vaneTCPC_wrapper{Conn: tls.Client(tcpConn, &tls.Config{InsecureSkipVerify: true})}}
		require.Same(t, tcpConn, vaneUnwrapTCPConn(chained))
	})

	t.Run("reflected unexported field", func(t *testing.T) {
		require.Same(t, tcpConn, vaneUnwrapTCPConn(&vaneTCPSecret_wrapper{hidden: tcpConn}))
	})

	t.Run("ambiguous fields refuse the guess", func(t *testing.T) {
		require.Nil(t, vaneUnwrapTCPConn(&vaneTCPDoubleConn{left: tcpConn, right: tcpConn}))
	})

	t.Run("cycle stops the walk", func(t *testing.T) {
		require.Nil(t, vaneUnwrapTCPConn(&vaneTCPCycleConn{Conn: tcpConn}))
	})

	t.Run("no connection field stops the walk", func(t *testing.T) {
		require.Nil(t, vaneUnwrapTCPConn(&vaneTCPSecret_wrapper{}))
	})

	t.Run("depth bound stops the walk", func(t *testing.T) {
		var current net.Conn = tcpConn
		for step := 0; step < vaneTCPUnwrapDepth+10; step++ {
			current = &vaneTCPU_wrapper{Conn: current}
		}
		require.Nil(t, vaneUnwrapTCPConn(current))
	})
}

func TestVaneTCPStatsLossRate(t *testing.T) {
	rate, ok := (*vaneTCPStats)(nil).lossRate()
	require.False(t, ok, "nil stats mean unsupported, never no loss")

	rate, ok = (&vaneTCPStats{segsOut: 1000, retransSegs: 7}).lossRate()
	require.True(t, ok)
	require.InDelta(t, 0.007, rate, 1e-9)

	rate, ok = (&vaneTCPStats{bytesSent: 10_000, bytesRetrans: 100}).lossRate()
	require.True(t, ok, "byte ratio is the fallback when segments are missing")
	require.InDelta(t, 0.01, rate, 1e-9)

	_, ok = (&vaneTCPStats{}).lossRate()
	require.False(t, ok, "a socket that never sent anything has no loss evidence")
}
