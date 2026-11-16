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

var errSageTestWrite = errors.New("sage test write failure")

type sageConnTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newSageConnTestClock() *sageConnTestClock {
	return &sageConnTestClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *sageConnTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *sageConnTestClock) Advance(elapsed time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(elapsed)
	c.mu.Unlock()
}

type sageConnTestRead struct {
	payload []byte
	err     error
}

type sageConnTestAddr string

func (a sageConnTestAddr) Network() string { return "sage-test" }
func (a sageConnTestAddr) String() string  { return string(a) }

type sageConnTestConn struct {
	mu sync.Mutex

	reads        []sageConnTestRead
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

func (c *sageConnTestConn) nextRead() sageConnTestRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reads) == 0 {
		return sageConnTestRead{err: io.EOF}
	}
	result := c.reads[0]
	c.reads = c.reads[1:]
	return result
}

func (c *sageConnTestConn) Read(payload []byte) (int, error) {
	if c.readFunc != nil {
		return c.readFunc(payload)
	}
	result := c.nextRead()
	return copy(payload, result.payload), result.err
}

func (c *sageConnTestConn) ReadBuffer(buffer *buf.Buffer) error {
	result := c.nextRead()
	if len(result.payload) > 0 {
		if _, err := buffer.Write(result.payload); err != nil {
			return err
		}
	}
	return result.err
}

func (c *sageConnTestConn) Write(payload []byte) (int, error) {
	if c.writeFunc != nil {
		return c.writeFunc(payload)
	}
	return len(payload), nil
}

func (c *sageConnTestConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writeBufFunc != nil {
		return c.writeBufFunc(buffer)
	}
	return nil
}

func (c *sageConnTestConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	closeFunc := c.closeFunc
	c.mu.Unlock()
	if closeFunc != nil {
		return closeFunc()
	}
	return nil
}

func (c *sageConnTestConn) LocalAddr() net.Addr  { return sageConnTestAddr("local") }
func (c *sageConnTestConn) RemoteAddr() net.Addr { return sageConnTestAddr("remote") }

func (c *sageConnTestConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sageConnTestConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sageConnTestConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sageConnTestConn) Chains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.chains...)
}

func (c *sageConnTestConn) ProviderChains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.providerChains...)
}

func (c *sageConnTestConn) AppendToChains(adapter C.ProxyAdapter) {
	c.mu.Lock()
	c.appendCalls++
	if adapter != nil {
		c.chains = append(c.chains, adapter.Name())
	}
	c.mu.Unlock()
}

func (c *sageConnTestConn) RemoteDestination() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteDestination
}

type sageConnTestCountConn struct {
	C.Conn
	readCount  atomic.Int64
	writeCount atomic.Int64
}

func (c *sageConnTestCountConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(count int64) { c.readCount.Add(count) }}
}

func (c *sageConnTestCountConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(count int64) { c.writeCount.Add(count) }}
}

type sagePacketConnTestFake struct {
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

func (c *sagePacketConnTestFake) ReadFrom(payload []byte) (int, net.Addr, error) {
	if c.readFromFunc != nil {
		return c.readFromFunc(payload)
	}
	return 0, nil, io.EOF
}

func (c *sagePacketConnTestFake) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	if c.waitReadFromFunc != nil {
		return c.waitReadFromFunc()
	}
	return nil, nil, nil, io.EOF
}

func (c *sagePacketConnTestFake) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	writeFunc := c.writeFunc
	c.mu.Unlock()
	if writeFunc != nil {
		return writeFunc(payload, address)
	}
	return len(payload), nil
}

func (c *sagePacketConnTestFake) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}

func (c *sagePacketConnTestFake) LocalAddr() net.Addr {
	return sageConnTestAddr("packet-local")
}

func (c *sagePacketConnTestFake) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sagePacketConnTestFake) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sagePacketConnTestFake) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *sagePacketConnTestFake) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (c *sagePacketConnTestFake) Chains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.chains...)
}

func (c *sagePacketConnTestFake) ProviderChains() C.Chain {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append(C.Chain(nil), c.providerChains...)
}

func (c *sagePacketConnTestFake) AppendToChains(adapter C.ProxyAdapter) {
	c.mu.Lock()
	c.appendCalls++
	if adapter != nil {
		c.chains = append(c.chains, adapter.Name())
	}
	c.mu.Unlock()
}

func (c *sagePacketConnTestFake) RemoteDestination() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteDestination
}

func TestSageFirstWriteDeferredExactlyOnce(t *testing.T) {
	t.Run("zero length and no progress defer settlement", func(t *testing.T) {
		var callbacks atomic.Int32
		underlying := &sageConnTestConn{
			writeFunc: func(payload []byte) (int, error) {
				if len(payload) == 1 && payload[0] == 1 {
					return 0, nil
				}
				return len(payload), nil
			},
		}
		wrapped := newFirstWriteSageCallbackConn(underlying, func(error) { callbacks.Add(1) })
		deferred := wrapped.(*firstWriteSageCallbackConn)
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
		underlying := &sageConnTestConn{writeFunc: func(payload []byte) (int, error) {
			return len(payload), errSageTestWrite
		}}
		var callbackErr error
		wrapped := newFirstWriteSageCallbackConn(underlying, func(err error) { callbackErr = err })
		if _, err := wrapped.Write([]byte("payload")); !errors.Is(err, errSageTestWrite) {
			t.Fatalf("Write error = %v, want %v", err, errSageTestWrite)
		}
		if callbackErr != nil {
			t.Fatalf("callback error = %v, want successful positive-byte settlement", callbackErr)
		}
	})

	t.Run("successful WriteBuffer settles once", func(t *testing.T) {
		underlying := &sageConnTestConn{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteSageCallbackConn(underlying, func(err error) {
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
		underlying := &sageConnTestConn{writeBufFunc: func(*buf.Buffer) error { return errSageTestWrite }}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		buffer := buf.As([]byte("payload"))
		defer buffer.Release()
		if err := wrapped.WriteBuffer(buffer); !errors.Is(err, errSageTestWrite) {
			t.Fatalf("WriteBuffer error = %v, want %v", err, errSageTestWrite)
		}
		if _, err := wrapped.Write([]byte("later")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 || !errors.Is(callbackErr, errSageTestWrite) {
			t.Fatalf("callback = (%d, %v), want (1, %v)", got, callbackErr, errSageTestWrite)
		}
	})

	t.Run("close before positive write settles neutral once", func(t *testing.T) {
		underlying := &sageConnTestConn{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteSageCallbackConn(underlying, func(err error) {
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
		underlying := &sageConnTestConn{writeFunc: func(payload []byte) (int, error) {
			close(writeEntered)
			<-releaseWrite
			return len(payload), nil
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstWriteSageCallbackConn(underlying, func(err error) {
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
		underlying := &sageConnTestConn{}
		var callbacks atomic.Int32
		wrapped := newFirstWriteSageCallbackConn(underlying, func(error) { callbacks.Add(1) })

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
		deferred := wrapped.(*firstWriteSageCallbackConn)
		if !deferred.WriterReplaceable() || !deferred.ReaderReplaceable() {
			t.Fatal("settled wrapper did not become replaceable")
		}
		if deferred.Upstream() != underlying {
			t.Fatal("Upstream did not preserve the wrapped connection")
		}
	})
}

func TestSageFirstResponseLifecycle(t *testing.T) {
	t.Run("requires a positive write and positive read", func(t *testing.T) {
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{
			{payload: []byte("server-push")},
			{err: io.EOF},
			{payload: []byte("response"), err: io.EOF},
		}}
		var mu sync.Mutex
		var responses []time.Duration
		wrapped := newSageObservedConn(underlying, clock, func(elapsed time.Duration) {
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
		clock := newSageConnTestClock()
		var writeCalls atomic.Int32
		underlying := &sageConnTestConn{
			reads: []sageConnTestRead{{payload: []byte("response"), err: io.EOF}},
			writeBufFunc: func(*buf.Buffer) error {
				if writeCalls.Add(1) == 1 {
					return errSageTestWrite
				}
				return nil
			},
		}
		var responses []time.Duration
		wrapped := newSageObservedConn(underlying, clock, func(elapsed time.Duration) {
			responses = append(responses, elapsed)
		}, nil)

		failed := buf.As([]byte("failed request"))
		defer failed.Release()
		if err := wrapped.WriteBuffer(failed); !errors.Is(err, errSageTestWrite) {
			t.Fatalf("failed WriteBuffer error = %v, want %v", err, errSageTestWrite)
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
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{
			{payload: []byte("read")},
			{payload: []byte("read-buffer")},
		}}
		var callbacks atomic.Int32
		wrapped := newSageObservedConn(underlying, clock, func(time.Duration) { callbacks.Add(1) }, nil)
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
		clock := newSageConnTestClock()
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &sageConnTestConn{
			readFunc: func(payload []byte) (int, error) { return copy(payload, []byte("response")), nil },
			writeFunc: func(payload []byte) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return len(payload), nil
			},
		}
		var mu sync.Mutex
		var responses []time.Duration
		wrapped := newSageObservedConn(underlying, clock, func(elapsed time.Duration) {
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
		clock := newSageConnTestClock()
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &sageConnTestConn{
			readFunc: func(payload []byte) (int, error) { return copy(payload, []byte("response")), nil },
			writeFunc: func([]byte) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return 0, errSageTestWrite
			},
		}
		var callbacks atomic.Int32
		wrapped := newSageObservedConn(underlying, clock, func(time.Duration) { callbacks.Add(1) }, nil)
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

func TestSageGoodputWindows(t *testing.T) {
	t.Run("five second active window settles immediately", func(t *testing.T) {
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
			{payload: make([]byte, 16*1024)},
		}}
		var samples []float64
		wrapped := newSageObservedConn(underlying, clock, nil, func(sample float64) { samples = append(samples, sample) })
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
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{
			{payload: make([]byte, 32*1024)},
			{payload: make([]byte, 32*1024)},
			{payload: []byte{1}},
		}}
		var samples []float64
		wrapped := newSageObservedConn(underlying, clock, nil, func(sample float64) { samples = append(samples, sample) })
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * time.Second)
		if _, err := wrapped.Read(make([]byte, 32*1024)); err != nil {
			t.Fatal(err)
		}
		clock.Advance(sageThroughputGap + time.Nanosecond)
		if _, err := wrapped.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if len(samples) != 1 || samples[0] != 8*float64(64*1024)/2 {
			t.Fatalf("samples = %v, want prior 64KiB/2s segment", samples)
		}
	})

	t.Run("Close settles an eligible tail exactly once", func(t *testing.T) {
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{
			{payload: make([]byte, 32*1024)},
			{payload: make([]byte, 32*1024)},
		}}
		var callbacks atomic.Int32
		wrapped := newSageObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
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
		clock := newSageConnTestClock()
		underlying := &sageConnTestConn{reads: []sageConnTestRead{{payload: make([]byte, 64*1024)}}}
		var callbacks atomic.Int32
		wrapped := newSageObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
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
				clock := newSageConnTestClock()
				underlying := &sageConnTestConn{reads: []sageConnTestRead{
					{payload: make([]byte, first)},
					{payload: make([]byte, test.bytes-first)},
				}}
				var callbacks atomic.Int32
				wrapped := newSageObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
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

func TestSageOptimizedCountCallbacks(t *testing.T) {
	clock := newSageConnTestClock()
	base := &sageConnTestConn{}
	counted := &sageConnTestCountConn{Conn: base}
	var responses atomic.Int32
	var throughput atomic.Int32
	wrapped := newSageObservedConn(counted, clock, func(time.Duration) { responses.Add(1) }, func(float64) { throughput.Add(1) })

	writer, writeCounters := SN.UnwrapCountWriter(wrapped, nil)
	reader, readCounters := SN.UnwrapCountReader(wrapped, nil)
	if _, ok := writer.(*sageObservedWriter); !ok || reader != base {
		t.Fatalf("initial optimized endpoints = (%T, %T), want sage pending writer and base reader", writer, reader)
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

func TestSageDeferredWriterWithSingCopy(t *testing.T) {
	base := &sageConnTestConn{}
	var handshakes atomic.Int32
	deferred := newFirstWriteSageCallbackConn(base, func(err error) {
		require.NoError(t, err)
		handshakes.Add(1)
	})
	observed := newSageObservedConn(deferred, newSageConnTestClock(), nil, nil)
	payload := bytes.Repeat([]byte("sage-copy"), 1024)

	copied, err := SBufio.Copy(observed, bytes.NewReader(payload))
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), copied)
	require.Equal(t, int32(1), handshakes.Load())
	require.True(t, deferred.(*firstWriteSageCallbackConn).WriterReplaceable())
}

func TestSageCloseConcurrentWithCompletedRead(t *testing.T) {
	clock := newSageConnTestClock()
	readEntered := make(chan struct{})
	releaseRead := make(chan struct{})
	var releaseOnce sync.Once
	var reads atomic.Int32
	underlying := &sageConnTestConn{}
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
	wrapped := newSageObservedConn(underlying, clock, nil, func(float64) { callbacks.Add(1) })
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

func TestSageUDPFirstPayloadExactlyOnce(t *testing.T) {
	t.Run("zero payload defers successful settlement", func(t *testing.T) {
		underlying := &sagePacketConnTestFake{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		if _, err := wrapped.WriteTo(nil, sageConnTestAddr("destination")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 0 {
			t.Fatalf("zero payload settled callback %d times", got)
		}
		if _, err := wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination")); err != nil {
			t.Fatal(err)
		}
		if got := callbacks.Load(); got != 1 || callbackErr != nil {
			t.Fatalf("successful callback = (%d, %v), want (1, nil)", got, callbackErr)
		}
	})

	t.Run("failure settles once even when WriteTo reports bytes", func(t *testing.T) {
		underlying := &sagePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			return len(payload), errSageTestWrite
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		if _, err := wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination")); !errors.Is(err, errSageTestWrite) {
			t.Fatalf("WriteTo error = %v, want %v", err, errSageTestWrite)
		}
		if _, err := wrapped.WriteTo([]byte("later"), sageConnTestAddr("destination")); !errors.Is(err, errSageTestWrite) {
			t.Fatalf("second WriteTo error = %v, want %v", err, errSageTestWrite)
		}
		if got := callbacks.Load(); got != 1 || !errors.Is(callbackErr, errSageTestWrite) {
			t.Fatalf("failed callback = (%d, %v), want (1, %v)", got, callbackErr, errSageTestWrite)
		}
	})

	t.Run("positive response before failed WriteTo return confirms the association", func(t *testing.T) {
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &sagePacketConnTestFake{
			writeFunc: func(payload []byte, _ net.Addr) (int, error) {
				close(writeEntered)
				<-releaseWrite
				return len(payload), errSageTestWrite
			},
			readFromFunc: func(payload []byte) (int, net.Addr, error) {
				return copy(payload, []byte("response")), sageConnTestAddr("source"), nil
			},
		}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination"))
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
		underlying := &sagePacketConnTestFake{}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		require.NoError(t, wrapped.Close())
		_, _ = wrapped.WriteTo([]byte("late"), sageConnTestAddr("destination"))
		require.Equal(t, int32(1), callbacks.Load())
		require.ErrorIs(t, callbackErr, net.ErrClosed)
	})

	t.Run("in-flight positive datagram wins over concurrent close", func(t *testing.T) {
		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		underlying := &sagePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			close(writeEntered)
			<-releaseWrite
			return len(payload), nil
		}}
		var callbacks atomic.Int32
		var callbackErr error
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(err error) {
			callbacks.Add(1)
			callbackErr = err
		})
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination"))
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
		underlying := &sagePacketConnTestFake{}
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(error) {})
		deferred := wrapped.(*firstPacketWriteSageCallbackConn)
		require.Same(t, underlying, deferred.Upstream())
		require.False(t, deferred.ReaderReplaceable())
		require.False(t, deferred.WriterReplaceable())
		require.True(t, deferred.ReaderPossiblyReplaceable())
		require.True(t, deferred.WriterPossiblyReplaceable())
		_, err := wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination"))
		require.NoError(t, err)
		require.True(t, deferred.ReaderReplaceable())
		require.True(t, deferred.WriterReplaceable())
		require.False(t, deferred.ReaderPossiblyReplaceable())
		require.False(t, deferred.WriterPossiblyReplaceable())
	})

	t.Run("concurrent positive payloads settle once", func(t *testing.T) {
		underlying := &sagePacketConnTestFake{}
		var callbacks atomic.Int32
		wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(error) { callbacks.Add(1) })
		const goroutines = 64
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wait.Done()
				<-start
				_, _ = wrapped.WriteTo([]byte("packet"), sageConnTestAddr("destination"))
			}()
		}
		close(start)
		wait.Wait()
		if got := callbacks.Load(); got != 1 {
			t.Fatalf("concurrent UDP callback count = %d, want 1", got)
		}
	})
}

func TestSageWrappersPreserveConnectionMetadataAndDeadlines(t *testing.T) {
	deadline := time.Unix(1_800_000_000, 0)
	readDeadline := deadline.Add(time.Second)
	writeDeadline := deadline.Add(2 * time.Second)
	underlying := &sageConnTestConn{
		chains:            C.Chain{"node", "group"},
		providerChains:    C.Chain{"provider"},
		remoteDestination: "example.test:443",
	}
	wrapped := newSageObservedConn(underlying, newSageConnTestClock(), nil, nil)
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

func TestSageUDPWrapperPreservesConnectionMetadataAndDeadlines(t *testing.T) {
	deadline := time.Unix(1_800_000_000, 0)
	underlying := &sagePacketConnTestFake{
		chains:            C.Chain{"udp-node"},
		providerChains:    C.Chain{"udp-provider"},
		remoteDestination: "dns.example:53",
	}
	wrapped := newFirstPacketWriteSageCallbackConn(underlying, func(error) {})
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
	_ C.Conn                       = (*sageConnTestConn)(nil)
	_ C.Conn                       = (*sageConnTestCountConn)(nil)
	_ C.PacketConn                 = (*sagePacketConnTestFake)(nil)
	_ SN.WriterPossiblyReplaceable = (*firstWriteSageCallbackConn)(nil)
	_ SN.ReaderPossiblyReplaceable = (*firstPacketWriteSageCallbackConn)(nil)
	_ SN.WriterPossiblyReplaceable = (*firstPacketWriteSageCallbackConn)(nil)
)
