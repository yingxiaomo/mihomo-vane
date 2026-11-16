//go:build linux

package outboundgroup

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	SBufio "github.com/metacubex/sing/common/bufio"
	SN "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/require"
)

type vaneLinuxSpliceClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *vaneLinuxSpliceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now
	c.now = c.now.Add(time.Second)
	return now
}

type vaneLinuxSpliceConn struct {
	N.ExtendedConn
	raw        net.Conn
	closeCalls atomic.Int32
}

func (c *vaneLinuxSpliceConn) Chains() C.Chain               { return nil }
func (c *vaneLinuxSpliceConn) ProviderChains() C.Chain       { return nil }
func (c *vaneLinuxSpliceConn) AppendToChains(C.ProxyAdapter) {}
func (c *vaneLinuxSpliceConn) RemoteDestination() string     { return "" }
func (c *vaneLinuxSpliceConn) ReaderReplaceable() bool       { return true }
func (c *vaneLinuxSpliceConn) WriterReplaceable() bool       { return true }
func (c *vaneLinuxSpliceConn) Upstream() any                 { return c.raw }
func (c *vaneLinuxSpliceConn) Close() error {
	c.closeCalls.Add(1)
	return c.ExtendedConn.Close()
}

func vaneLinuxTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timeout")
	}
	return nil, nil
}

func TestVaneControlledConnLinuxSpliceClosesAfterDeliveredChunk(t *testing.T) {
	sourceWriter, sourceReader := vaneLinuxTCPPair(t)
	destinationWriter, destinationReader := vaneLinuxTCPPair(t)
	deadline := time.Now().Add(30 * time.Second)
	for _, conn := range []*net.TCPConn{sourceWriter, sourceReader, destinationWriter, destinationReader} {
		require.NoError(t, conn.SetDeadline(deadline))
		defer conn.Close()
	}

	underlying := &vaneLinuxSpliceConn{ExtendedConn: N.NewExtendedConn(sourceReader), raw: sourceReader}
	clock := &vaneLinuxSpliceClock{now: time.Unix(1, 0)}
	var windows atomic.Int32
	var committed atomic.Int32
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		if windows.Add(1) < 3 {
			return nil
		}
		return func() bool {
			committed.Add(1)
			return true
		}
	})
	unwrapped, counters := SN.UnwrapCountReader(wrapped, nil)
	_, rawTCP := unwrapped.(*net.TCPConn)
	require.True(t, rawTCP, "source must unwrap to a raw TCP socket")
	require.NotEmpty(t, counters, "vane post-delivery counter must survive unwrapping")

	payload := bytes.Repeat([]byte{0x5a}, 40*1024*1024)
	producerDone := make(chan struct{})
	go func() {
		_, _ = sourceWriter.Write(payload)
		_ = sourceWriter.CloseWrite()
		close(producerDone)
	}()

	receivedCh := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, destinationReader)
		receivedCh <- n
	}()

	_, _ = SBufio.Copy(destinationWriter, wrapped)
	_ = destinationWriter.Close()
	received := <-receivedCh
	<-producerDone
	observed := wrapped.(*vaneObservedConn)
	observed.mu.Lock()
	deliveredCounted := observed.totalReadBytes
	observed.mu.Unlock()
	require.GreaterOrEqual(t, windows.Load(), int32(3))
	require.Equal(t, int32(1), committed.Load())
	require.Equal(t, int32(1), underlying.closeCalls.Load())
	require.Equal(t, deliveredCounted, received, "every splice-counted byte must reach the destination")
	require.Greater(t, received, int64(0))
}
