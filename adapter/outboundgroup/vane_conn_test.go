package outboundgroup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	SBufio "github.com/metacubex/sing/common/bufio"
	SN "github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/require"
)

var errVaneTestWrite = errors.New("vane test write failure")

type vaneConnTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newVaneConnTestClock() *vaneConnTestClock {
	return &vaneConnTestClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *vaneConnTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *vaneConnTestClock) Advance(elapsed time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(elapsed)
	c.mu.Unlock()
}

type vaneConnTestRead struct {
	payload []byte
	err     error
}

type vaneConnTestAddr string

func (a vaneConnTestAddr) Network() string { return "vane-test" }
func (a vaneConnTestAddr) String() string  { return string(a) }

type vaneConnTestConn struct {
	mu sync.Mutex

	reads        []vaneConnTestRead
	readFunc     func([]byte) (int, error)
	writeFunc    func([]byte) (int, error)
	writeBufFunc func(*buf.Buffer) error
	closeFunc    func() error

	closeCalls        int
	appendCalls       int
	chains            C.Chain
	providerChains    C.Chain
	remoteDestination string
	deadline          time.Time
	readDeadline      time.Time
	writeDeadline     time.Time
}

func (c *vaneConnTestConn) nextRead() vaneConnTestRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reads) == 0 {
		return vaneConnTestRead{err: io.EOF}
	}
	result := c.reads[0]
	c.reads = c.reads[1:]
	return result
}

func (c *vaneConnTestConn) Read(payload []byte) (int, error) {
	if c.readFunc != nil {
		return c.readFunc(payload)
	}
	result := c.nextRead()
	return copy(payload, result.payload), result.err
}

func (c *vaneConnTestConn) ReadBuffer(buffer *buf.Buffer) error {
	result := c.nextRead()
	if len(result.payload) > 0 {
		if _, err := buffer.Write(result.payload); err != nil {
			return err
		}
	}
	return result.err
}

func (c *vaneConnTestConn) Write(payload []byte) (int, error) {
	if c.writeFunc != nil {
		return c.writeFunc(payload)
	}
	return len(payload), nil
}

func (c *vaneConnTestConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writeBufFunc != nil {
		return c.writeBufFunc(buffer)
	}
	return nil
}

func (c *vaneConnTestConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	closeFunc := c.closeFunc
	c.mu.Unlock()
	if closeFunc != nil {
		return closeFunc()
	}
	return nil
}

func (c *vaneConnTestConn) LocalAddr() net.Addr  { return vaneConnTestAddr("local") }
func (c *vaneConnTestConn) RemoteAddr() net.Addr { return vaneConnTestAddr("remote") }

func (c *vaneConnTestConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vaneConnTestConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vaneConnTestConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vaneConnTestConn) Chains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.chains...)
}

func (c *vaneConnTestConn) ProviderChains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.providerChains...)
}

func (c *vaneConnTestConn) AppendToChains(adapter C.ProxyAdapter) {
	c.mu.Lock()
	c.appendCalls++
	if adapter != nil {
		c.chains = append(c.chains, adapter.Name())
	}
	c.mu.Unlock()
}

func (c *vaneConnTestConn) RemoteDestination() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteDestination
}

type vaneConnTestCountConn struct {
	C.Conn
	readCount  atomic.Int64
	writeCount atomic.Int64
}

func (c *vaneConnTestCountConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(count int64) { c.readCount.Add(count) }}
}

func (c *vaneConnTestCountConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(count int64) { c.writeCount.Add(count) }}
}

type vanePacketConnTestFake struct {
	mu sync.Mutex

	writeFunc         func([]byte, net.Addr) (int, error)
	readFromFunc      func([]byte) (int, net.Addr, error)
	waitReadFromFunc  func() ([]byte, func(), net.Addr, error)
	writes            int
	closeCalls        int
	appendCalls       int
	deadline          time.Time
	readDeadline      time.Time
	writeDeadline     time.Time
	chains            C.Chain
	providerChains    C.Chain
	remoteDestination string
}

func (c *vanePacketConnTestFake) ReadFrom(payload []byte) (int, net.Addr, error) {
	if c.readFromFunc != nil {
		return c.readFromFunc(payload)
	}
	return 0, nil, io.EOF
}

func (c *vanePacketConnTestFake) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	if c.waitReadFromFunc != nil {
		return c.waitReadFromFunc()
	}
	return nil, nil, nil, io.EOF
}

func (c *vanePacketConnTestFake) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	writeFunc := c.writeFunc
	c.mu.Unlock()
	if writeFunc != nil {
		return writeFunc(payload, address)
	}
	return len(payload), nil
}

func (c *vanePacketConnTestFake) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}

func (c *vanePacketConnTestFake) LocalAddr() net.Addr {
	return vaneConnTestAddr("packet-local")
}

func (c *vanePacketConnTestFake) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vanePacketConnTestFake) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vanePacketConnTestFake) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *vanePacketConnTestFake) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (c *vanePacketConnTestFake) Chains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.chains...)
}

func (c *vanePacketConnTestFake) ProviderChains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.providerChains...)
}

func (c *vanePacketConnTestFake) AppendToChains(adapter C.ProxyAdapter) {
	c.mu.Lock()
	c.appendCalls++
	if adapter != nil {
		c.chains = append(c.chains, adapter.Name())
	}
	c.mu.Unlock()
}

func (c *vanePacketConnTestFake) RemoteDestination() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteDestination
}

func TestVaneFirstWriteDeferredExactlyOnce(t *testing.T) {
	t.Run("zero length and no progress defer settlement", func(t *testing.T) {
		var callbacks atomic.Int32
		underlying := &vaneConnTestConn{
			writeFunc: func(payload []byte) (int, error) {
				if len(payload) == 1 && payload[0] == 1 {
					return 0, nil
				}
				return len(payload), nil
			},
		}
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(error) { callbacks.Add(1) })
		deferred := wrapped.(*firstWriteVaneCallbackConn)
		if deferred.WriterReplaceable() || !deferred.WriterPossiblyReplaceable() {
			t.Fatal("unsettled deferred writer did not advertise future replaceability")
		}
		if _, err := wrapped.Write(nil); err != nil {
			t.Fatal(err)
		}
		if _, err := wrapped.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		empty := buf.NewSize(0)
		defer empty.Release()
		if err := wrapped.WriteBuffer(empty); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 0 {
			t.Fatalf("zero-progress writes settled callback %d times", got)
		}
		if _, err := wrapped.Write([]byte{2}); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 {
			t.Fatalf("positive write settled callback %d times, want 1", got)
		}
	})

	t.Run("positive bytes win over accompanying error", func(t *testing.T) {
		underlying := &vaneConnTestConn{writeFunc: func(payload []byte) (int, error) {
			return len(payload), errVaneTestWrite
		}}
		var callbackErr error
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(err error) { callbackErr = err })
		if _, err := wrapped.Write([]byte("payload")); !errors.Is(err, errVaneTestWrite) {
			t.Fatalf("Write error = %v, want %v", err, errVaneTestWrite)
		}
		if callbackErr != nil {
			t.Fatalf("callback error = %v, want successful positive-byte settlement", callbackErr)
		}
	})

	t.Run("successful WriteBuffer settles once", func(t *testing.T) {
		underlying := &vaneConnTestConn{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		buffer := buf.As([]byte("payload"))
		defer buffer.Release()
		if err := wrapped.WriteBuffer(buffer); err != nil {
			t.Fatal(err)
		}
		if _, err := wrapped.Write([]byte("later")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 || callbackErr != nil {
			t.Fatalf("callback = (%d, %v), want (1, nil)", got, callbackErr)
		}
	})

	t.Run("WriteBuffer failure settles once", func(t *testing.T) {
		underlying := &vaneConnTestConn{writeBufFunc: func(*buf.Buffer) error { return errVaneTestWrite }}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		buffer := buf.As([]byte("payload"))
		defer buffer.Release()
		if err := wrapped.WriteBuffer(buffer); !errors.Is(err, errVaneTestWrite) {
			t.Fatalf("WriteBuffer error = %v, want %v", err, errVaneTestWrite)
		}
		if _, err := wrapped.Write([]byte("later")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 || !errors.Is(callbackErr, errVaneTestWrite) {
			t.Fatalf("callback = (%d, %v), want (1, %v)", got, callbackErr, errVaneTestWrite)
		}
	})

	t.Run("close before positive write settles neutral once", func(t *testing.T) {
		underlying := &vaneConnTestConn{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		require.NoError(t, wrapped.Close())
		_, _ = wrapped.Write([]byte("late"))
		require.Equal(t, int32(1), callbacks.Load())
		require.ErrorIs(t, callbackErr, net.ErrClosed)
	})

	t.Run("in-flight positive write wins over concurrent close", func(t *testing.T) {
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &vaneConnTestConn{writeFunc: func(payload []byte) (int, error) {
			close(writeEntered)
			<-releaseWrite
			return len(payload), nil
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.Write([]byte("payload"))
		}()
		<-writeEntered
		require.NoError(t, wrapped.Close())
		require.Zero(t, callbacks.Load())
		close(releaseWrite)
		<-writeDone
		require.Equal(t, int32(1), callbacks.Load())
		require.NoError(t, callbackErr)
	})

	t.Run("concurrent Write and WriteBuffer settle once", func(t *testing.T) {
		underlying := &vaneConnTestConn{}
		var callbacks atomic.Int32
		wrapped := newFirstWriteVaneCallbackConn(underlying, func(error) { callbacks.Add(1) })

		const goroutines = 64
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func(useBuffer bool) {
				defer wait.Done()
				<-start
				if useBuffer {
					buffer := buf.As([]byte("buffered"))
					defer buffer.Release()
					_ = wrapped.WriteBuffer(buffer)
					return
				}
				_, _ = wrapped.Write([]byte("direct"))
			}(i%2 == 0)
		}
		close(start)
		wait.Wait()

		if got := callbacks.Load(); got != 1 {
			t.Fatalf("concurrent callback count = %d, want 1", got)
		}
		deferred := wrapped.(*firstWriteVaneCallbackConn)
		if !deferred.WriterReplaceable() || !deferred.ReaderReplaceable() {
			t.Fatal("settled wrapper did not become replaceable")
		}
		if deferred.Upstream() != underlying {
			t.Fatal("Upstream did not preserve the wrapped connection")
		}
	})
}

func TestVaneFirstResponseLifecycle(t *testing.T) {
	t.Run("requires a positive write and positive read", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
			{payload: []byte("server-push")},
			{err: io.EOF},
			{payload: []byte("response"), err: io.EOF},
		}}
		var mu sync.Mutex
		var responses []time.Duration
		wrapped := newVaneObservedConn(underlying, clock, func(elapsed time.Duration) {
			mu.Lock()
			responses = append(responses, elapsed)
			mu.Unlock()
		}, nil)

		readBuffer := make([]byte, 32)
		if n, err := wrapped.Read(readBuffer); n == 0 || err != nil {
			t.Fatalf("server-push Read = (%d, %v), want positive read", n, err)
		}
		if _, err := wrapped.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		clock.Advance(125 * time.Millisecond)
		if n, err := wrapped.Read(readBuffer); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("zero-byte Read = (%d, %v), want (0, EOF)", n, err)
		}
		clock.Advance(75 * time.Millisecond)
		if n, err := wrapped.Read(readBuffer); n == 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("positive EOF Read = (%d, %v), want positive bytes with EOF", n, err)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(responses) != 1 || responses[0] != 200*time.Millisecond {
			t.Fatalf("response samples = %v, want [200ms]", responses)
		}
	})

	t.Run("buffered response starts after successful buffered write", func(t *testing.T) {
		clock := newVaneConnTestClock()
		var writeCalls atomic.Int32
		underlying := &vaneConnTestConn{
			reads: []vaneConnTestRead{{payload: []byte("response"), err: io.EOF}},
			writeBufFunc: func(*buf.Buffer) error {
				if writeCalls.Add(1) == 1 {
					return errVaneTestWrite
				}
				return nil
			},
		}
		var responses []time.Duration
		wrapped := newVaneObservedConn(underlying, clock, func(elapsed time.Duration) {
			responses = append(responses, elapsed)
		}, nil)

		failed := buf.As([]byte("failed request"))
		defer failed.Release()
		if err := wrapped.WriteBuffer(failed); !errors.Is(err, errVaneTestWrite) {
			t.Fatalf("failed WriteBuffer error = %v, want %v", err, errVaneTestWrite)
		}
		clock.Advance(time.Second)
		successful := buf.As([]byte("successful request"))
		defer successful.Release()
		if err := wrapped.WriteBuffer(successful); err != nil {
			t.Fatal(err)
		}
		clock.Advance(250 * time.Millisecond)
		response := buf.NewSize(32)
		defer response.Release()
		if err := wrapped.ReadBuffer(response); !errors.Is(err, io.EOF) {
			t.Fatalf("ReadBuffer error = %v, want EOF accompanying bytes", err)
		}
		if len(responses) != 1 || responses[0] != 250*time.Millisecond {
			t.Fatalf("buffered response samples = %v, want [250ms]", responses)
		}
	})

	t.Run("Read and ReadBuffer mixed record at most once", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
			{payload: []byte("read")},
			{payload: []byte("read-buffer")},
		}}
		var callbacks atomic.Int32
		wrapped := newVaneObservedConn(underlying, clock, func(time.Duration) { callbacks.Add(1) }, nil)
		if _, err := wrapped.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)

		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _ = wrapped.Read(make([]byte, 32))
		}()
		go func() {
			defer wait.Done()
			<-start
			buffer := buf.NewSize(32)
			defer buffer.Release()
			_ = wrapped.ReadBuffer(buffer)
		}()
		close(start)
		wait.Wait()

		if got := callbacks.Load(); got != 1 {
			t.Fatalf("mixed read callback count = %d, want 1", got)
		}
	})
	t.Run("response concurrent with a pending successful write settles provisionally", func(t *testing.T) {
		clock := newVaneConnTestClock()
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &vaneConnTestConn{
			readFunc: func(payload []byte) (int, error) { return copy(payload, []byte("response")), nil },
			writeFunc: func(payload []byte) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return len(payload), nil
			},
		}
		var mu sync.Mutex
		var responses []time.Duration
		wrapped := newVaneObservedConn(underlying, clock, func(elapsed time.Duration) {
			mu.Lock()
			responses = append(responses, elapsed)
			mu.Unlock()
		}, nil)

		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.Write([]byte("request"))
		}()
		<-writeEntered
		if n, err := wrapped.Read(make([]byte, 32)); n == 0 || err != nil {
			t.Fatalf("concurrent response Read = (%d, %v)", n, err)
		}
		mu.Lock()
		require.Empty(t, responses, "response must wait for send confirmation")
		mu.Unlock()
		clock.Advance(100 * time.Millisecond)
		close(releaseWrite)
		<-writeDone
		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, []time.Duration{0}, responses)
	})

	t.Run("response concurrent with a failed write is discarded", func(t *testing.T) {
		clock := newVaneConnTestClock()
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &vaneConnTestConn{
			readFunc: func(payload []byte) (int, error) { return copy(payload, []byte("response")), nil },
			writeFunc: func([]byte) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return 0, errVaneTestWrite
			},
		}
		var callbacks atomic.Int32
		wrapped := newVaneObservedConn(underlying, clock, func(time.Duration) { callbacks.Add(1) }, nil)
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.Write([]byte("request"))
		}()
		<-writeEntered
		if n, err := wrapped.Read(make([]byte, 32)); n == 0 || err != nil {
			t.Fatalf("concurrent response Read = (%d, %v)", n, err)
		}
		close(releaseWrite)
		<-writeDone
		require.Zero(t, callbacks.Load())
	})
}

func TestVaneGoodputWindows(t *testing.T) {
	t.Run("five second active window settles immediately", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
		}}
		var samples []float64
		wrapped := newVaneObservedConn(underlying, clock, nil, func(sample float64) { samples = append(samples, sample) })
		if _, err := wrapped.Read(make([]byte, 16*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Second)
		if _, err := wrapped.Read(make([]byte, 16*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Second)
		if _, err := wrapped.Read(make([]byte, 16*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
		buffer := buf.NewSize(16 * 1024)
		defer buffer.Release()
		if err := wrapped.ReadBuffer(buffer); err != nil {
			t.Fatal(err)
		}
		if len(samples) != 1 || samples[0] != 8*float64(64*1024)/5 {
			t.Fatalf("samples = %v, want one 64KiB/5s sample", samples)
		}
		if err := wrapped.Close(); err != nil {
			t.Fatal(err)
		}
		if len(samples) != 1 {
			t.Fatalf("Close duplicated completed sample: %v", samples)
		}
	})

	t.Run("gap greater than two seconds closes prior segment", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
			{payload: make([]byte, 32*1024)},
			{payload: make([]byte, 32*1024)},
			{payload: []byte{1}},
		}}
		var samples []float64
		wrapped := newVaneObservedConn(underlying, clock, nil, func(sample float64) { samples = append(samples, sample) })
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Second)
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(vaneThroughputGap + time.Nanosecond)
		if _, err := wrapped.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if len(samples) != 1 || samples[0] != 8*float64(64*1024)/2 {
			t.Fatalf("samples = %v, want prior 64KiB/2s segment", samples)
		}
	})

	t.Run("Close settles an eligible tail exactly once", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
			{payload: make([]byte, 32*1024)},
			{payload: make([]byte, 32*1024)},
		}}
		var callbacks atomic.Int32
		wrapped := newVaneObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Second)
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}

		const closes = 32
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(closes)
		for i := 0; i < closes; i++ {
			go func() {
				defer wait.Done()
				<-start
				_ = wrapped.Close()
			}()
		}
		close(start)
		wait.Wait()
		if got := callbacks.Load(); got != 1 {
			t.Fatalf("concurrent Close callback count = %d, want 1", got)
		}
	})

	t.Run("idle time creates no zero goodput", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{reads: []vaneConnTestRead{{payload: make([]byte, 64*1024)}}}
		var callbacks atomic.Int32
		wrapped := newVaneObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
		if _, err := wrapped.Read(make([]byte, 64*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Hour)
		if err := wrapped.Close(); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 0 {
			t.Fatalf("idle connection emitted %d goodput samples", got)
		}
	})

	t.Run("64KiB and two seconds are inclusive boundaries", func(t *testing.T) {
		tests := []struct {
			name     string
			bytes    int
			duration time.Duration
			want     bool
		}{
			{name: "exact", bytes: 64 * 1024, duration: 2 * time.Second, want: true},
			{name: "one byte short", bytes: 64*1024 - 1, duration: 2 * time.Second},
			{name: "one nanosecond short", bytes: 64 * 1024, duration: 2*time.Second - time.Nanosecond},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				first := test.bytes / 2
				clock := newVaneConnTestClock()
				underlying := &vaneConnTestConn{reads: []vaneConnTestRead{
					{payload: make([]byte, first)},
					{payload: make([]byte, test.bytes-first)},
				}}
				var callbacks atomic.Int32
				wrapped := newVaneObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
				if _, err := wrapped.Read(make([]byte, first)); err != nil {
					t.Fatal(err)
				}
				clock.Advance(test.duration)
				if _, err := wrapped.Read(make([]byte, test.bytes-first)); err != nil {
					t.Fatal(err)
				}
				if err := wrapped.Close(); err != nil {
					t.Fatal(err)
				}
				want := int32(0)
				if test.want {
					want = 1
				}
				if got := callbacks.Load(); got != want {
					t.Fatalf("callback count = %d, want %d", got, want)
				}
			})
		}
	})
}

func TestVaneOptimizedCountCallbacks(t *testing.T) {
	clock := newVaneConnTestClock()
	base := &vaneConnTestConn{}
	counted := &vaneConnTestCountConn{Conn: base}
	var responses atomic.Int32
	var throughput atomic.Int32
	wrapped := newVaneObservedConn(counted, clock, func(time.Duration) { responses.Add(1) }, func(float64) { throughput.Add(1) })

	writer, writeCounters := SN.UnwrapCountWriter(wrapped, nil)
	reader, readCounters := SN.UnwrapCountReader(wrapped, nil)
	if _, ok := writer.(*vaneObservedWriter); !ok || reader != base {
		t.Fatalf("initial optimized endpoints = (%T, %T), want vane pending writer and base reader", writer, reader)
	}
	if len(writeCounters) != 1 || len(readCounters) != 2 {
		t.Fatalf("initial counter lengths = (write %d, read %d), want (1, 2)", len(writeCounters), len(readCounters))
	}

	n, err := writer.Write([]byte("payload"))
	if err != nil || n != 7 {
		t.Fatalf("first optimized Write = (%d, %v), want (7, nil)", n, err)
	}
	writer, writeCounters = SN.UnwrapCountWriter(writer, writeCounters)
	if writer != base || len(writeCounters) != 2 {
		t.Fatalf("settled optimized writer = (%T, %d counters), want base and 2", writer, len(writeCounters))
	}
	for _, counter := range writeCounters {
		counter(int64(n))
	}
	clock.Advance(2 * time.Second)
	for _, counter := range readCounters {
		counter(32 * 1024)
	}
	clock.Advance(2 * time.Second)
	for _, counter := range readCounters {
		counter(32 * 1024)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}

	if got := counted.writeCount.Load(); got != 7 {
		t.Fatalf("upstream write counter = %d, want 7", got)
	}
	if got := counted.readCount.Load(); got != 64*1024 {
		t.Fatalf("upstream read counter = %d, want 64KiB", got)
	}
	if got := responses.Load(); got != 1 {
		t.Fatalf("optimized response callbacks = %d, want 1", got)
	}
	if got := throughput.Load(); got != 1 {
		t.Fatalf("optimized throughput callbacks = %d, want 1", got)
	}
}

func TestVaneDeferredWriterWithSingCopy(t *testing.T) {
	base := &vaneConnTestConn{}
	var handshakes atomic.Int32
	deferred := newFirstWriteVaneCallbackConn(base, func(err error) {
		require.NoError(t, err)
		handshakes.Add(1)
	})
	observed := newVaneObservedConn(deferred, newVaneConnTestClock(), nil, nil)
	payload := bytes.Repeat([]byte("vane-copy"), 1024)

	copied, err := SBufio.Copy(observed, bytes.NewReader(payload))
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), copied)
	require.Equal(t, int32(1), handshakes.Load())
	require.True(t, deferred.(*firstWriteVaneCallbackConn).WriterReplaceable())
}

func TestVaneCloseConcurrentWithCompletedRead(t *testing.T) {
	clock := newVaneConnTestClock()
	readEntered := make(chan struct{})
	releaseRead := make(chan struct{})
	var releaseOnce sync.Once
	var reads atomic.Int32
	underlying := &vaneConnTestConn{}
	underlying.readFunc = func(payload []byte) (int, error) {
		if reads.Add(1) == 1 {
			return copy(payload, make([]byte, 32*1024)), nil
		}
		close(readEntered)
		<-releaseRead
		return copy(payload, make([]byte, 32*1024)), nil
	}
	underlying.closeFunc = func() error {
		releaseOnce.Do(func() { close(releaseRead) })
		return nil
	}

	var callbacks atomic.Int32
	wrapped := newVaneObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
	if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = wrapped.Read(make([]byte, 32*1024))
	}()
	<-readEntered
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	<-readDone
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if got := callbacks.Load(); got != 1 {
		t.Fatalf("Close racing a completed read produced %d tail samples, want 1", got)
	}
}

func TestVaneUDPFirstPayloadExactlyOnce(t *testing.T) {
	t.Run("zero payload defers successful settlement", func(t *testing.T) {
		underlying := &vanePacketConnTestFake{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		if _, err := wrapped.WriteTo(nil, vaneConnTestAddr("destination")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 0 {
			t.Fatalf("zero payload settled callback %d times", got)
		}
		if _, err := wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 || callbackErr != nil {
			t.Fatalf("successful callback = (%d, %v), want (1, nil)", got, callbackErr)
		}
	})

	t.Run("failure settles once even when WriteTo reports bytes", func(t *testing.T) {
		underlying := &vanePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			return len(payload), errVaneTestWrite
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		if _, err := wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination")); !errors.Is(err, errVaneTestWrite) {
			t.Fatalf("WriteTo error = %v, want %v", err, errVaneTestWrite)
		}
		if _, err := wrapped.WriteTo([]byte("later"), vaneConnTestAddr("destination")); !errors.Is(err, errVaneTestWrite) {
			t.Fatalf("second WriteTo error = %v, want %v", err, errVaneTestWrite)
		}
		if got := callbacks.Load(); got != 1 || !errors.Is(callbackErr, errVaneTestWrite) {
			t.Fatalf("failed callback = (%d, %v), want (1, %v)", got, callbackErr, errVaneTestWrite)
		}
	})

	t.Run("positive response before failed WriteTo return confirms the association", func(t *testing.T) {
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &vanePacketConnTestFake{
			writeFunc: func(payload []byte, _ net.Addr) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return len(payload), errVaneTestWrite
			},
			readFromFunc: func(payload []byte) (int, net.Addr, error) {
				return copy(payload, []byte("response")), vaneConnTestAddr("source"), nil
			},
		}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
		}()
		<-writeEntered
		if n, _, err := wrapped.ReadFrom(make([]byte, 32)); n == 0 || err != nil {
			t.Fatalf("ReadFrom = (%d, %v), want positive response", n, err)
		}
		require.Zero(t, callbacks.Load(), "settlement must wait for WriteTo confirmation")
		close(releaseWrite)
		<-writeDone
		require.Equal(t, int32(1), callbacks.Load())
		require.NoError(t, callbackErr)
	})

	t.Run("close before positive datagram settles neutral once", func(t *testing.T) {
		underlying := &vanePacketConnTestFake{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		require.NoError(t, wrapped.Close())
		_, _ = wrapped.WriteTo([]byte("late"), vaneConnTestAddr("destination"))
		require.Equal(t, int32(1), callbacks.Load())
		require.ErrorIs(t, callbackErr, net.ErrClosed)
	})

	t.Run("in-flight positive datagram wins over concurrent close", func(t *testing.T) {
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &vanePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			close(writeEntered)
			<-releaseWrite
			return len(payload), nil
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
		}()
		<-writeEntered
		require.NoError(t, wrapped.Close())
		require.Zero(t, callbacks.Load())
		close(releaseWrite)
		<-writeDone
		require.Equal(t, int32(1), callbacks.Load())
		require.NoError(t, callbackErr)
	})

	t.Run("wrapper preserves upstream and dynamic replaceability", func(t *testing.T) {
		underlying := &vanePacketConnTestFake{}
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(error) {})
		deferred := wrapped.(*firstPacketWriteVaneCallbackConn)
		require.Same(t, underlying, deferred.Upstream())
		require.False(t, deferred.ReaderReplaceable())
		require.False(t, deferred.WriterReplaceable())
		require.True(t, deferred.ReaderPossiblyReplaceable())
		require.True(t, deferred.WriterPossiblyReplaceable())
		_, err := wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
		require.NoError(t, err)
		require.True(t, deferred.ReaderReplaceable())
		require.True(t, deferred.WriterReplaceable())
		require.False(t, deferred.ReaderPossiblyReplaceable())
		require.False(t, deferred.WriterPossiblyReplaceable())
	})

	t.Run("concurrent positive payloads settle once", func(t *testing.T) {
		underlying := &vanePacketConnTestFake{}
		var callbacks atomic.Int32
		wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(error) { callbacks.Add(1) })
		const goroutines = 64
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wait.Done()
				<-start
				_, _ = wrapped.WriteTo([]byte("packet"), vaneConnTestAddr("destination"))
			}()
		}
		close(start)
		wait.Wait()
		if got := callbacks.Load(); got != 1 {
			t.Fatalf("concurrent UDP callback count = %d, want 1", got)
		}
	})
}

func TestVaneWrappersPreserveConnectionMetadataAndDeadlines(t *testing.T) {
	deadline := time.Unix(1_800_000_000, 0)
	readDeadline := deadline.Add(time.Second)
	writeDeadline := deadline.Add(2 * time.Second)
	underlying := &vaneConnTestConn{
		chains:            C.Chain{"node", "group"},
		providerChains:    C.Chain{"provider"},
		remoteDestination: "example.test:443",
	}
	wrapped := newVaneObservedConn(underlying, newVaneConnTestClock(), nil, nil)
	if err := wrapped.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.SetReadDeadline(readDeadline); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatal(err)
	}
	wrapped.AppendToChains(nil)

	if got := wrapped.Chains().String(); got != underlying.Chains().String() {
		t.Fatalf("Chains = %q, want %q", got, underlying.Chains().String())
	}
	if got := wrapped.ProviderChains().String(); got != "provider" {
		t.Fatalf("ProviderChains = %q, want provider", got)
	}
	if got := wrapped.RemoteDestination(); got != "example.test:443" {
		t.Fatalf("RemoteDestination = %q", got)
	}
	underlying.mu.Lock()
	defer underlying.mu.Unlock()
	if underlying.deadline != deadline || underlying.readDeadline != readDeadline || underlying.writeDeadline != writeDeadline {
		t.Fatalf("deadlines = (%v, %v, %v), want (%v, %v, %v)", underlying.deadline, underlying.readDeadline, underlying.writeDeadline, deadline, readDeadline, writeDeadline)
	}
	if underlying.appendCalls != 1 {
		t.Fatalf("AppendToChains calls = %d, want 1", underlying.appendCalls)
	}
}

func TestVaneUDPWrapperPreservesConnectionMetadataAndDeadlines(t *testing.T) {
	deadline := time.Unix(1_800_000_000, 0)
	underlying := &vanePacketConnTestFake{
		chains:            C.Chain{"udp-node"},
		providerChains:    C.Chain{"udp-provider"},
		remoteDestination: "dns.example:53",
	}
	wrapped := newFirstPacketWriteVaneCallbackConn(underlying, func(error) {})
	if err := wrapped.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.SetReadDeadline(deadline.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.SetWriteDeadline(deadline.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wrapped.AppendToChains(nil)
	if got := wrapped.Chains().String(); got != "udp-node" {
		t.Fatalf("Chains = %q, want udp-node", got)
	}
	if got := wrapped.ProviderChains().String(); got != "udp-provider" {
		t.Fatalf("ProviderChains = %q, want udp-provider", got)
	}
	if got := wrapped.RemoteDestination(); got != "dns.example:53" {
		t.Fatalf("RemoteDestination = %q", got)
	}
	if err := wrapped.ResolveUDP(context.Background(), &C.Metadata{}); err != nil {
		t.Fatal(err)
	}
	underlying.mu.Lock()
	defer underlying.mu.Unlock()
	if underlying.deadline != deadline || underlying.readDeadline != deadline.Add(time.Second) || underlying.writeDeadline != deadline.Add(2*time.Second) {
		t.Fatal("UDP deadlines were not forwarded")
	}
	if underlying.appendCalls != 1 {
		t.Fatalf("AppendToChains calls = %d, want 1", underlying.appendCalls)
	}
}

var (
	_ C.Conn                       = (*vaneConnTestConn)(nil)
	_ C.Conn                       = (*vaneConnTestCountConn)(nil)
	_ C.PacketConn                 = (*vanePacketConnTestFake)(nil)
	_ SN.WriterPossiblyReplaceable = (*firstWriteVaneCallbackConn)(nil)
	_ SN.ReaderPossiblyReplaceable = (*firstPacketWriteVaneCallbackConn)(nil)
	_ SN.WriterPossiblyReplaceable = (*firstPacketWriteVaneCallbackConn)(nil)
)
