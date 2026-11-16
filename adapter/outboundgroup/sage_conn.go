package outboundgroup

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

const (
	sageThroughputGap        = 2 * time.Second
	sageThroughputWindow     = 5 * time.Second
	sageThroughputMinWindow  = 2 * time.Second
	sageThroughputMinPayload = 64 * 1024
)

// firstWriteSageCallbackConn settles a deferred handshake exactly once on
// the first non-empty write attempt. Zero-length writes carry no evidence.
type firstWriteSageCallbackConn struct {
	C.Conn
	once     sync.Once
	settled  atomic.Bool
	callback func(error)

	mu           sync.Mutex
	pending      int
	closePending bool
	decisionMade bool
}

func newFirstWriteSageCallbackConn(conn C.Conn, callback func(error)) C.Conn {
	return &firstWriteSageCallbackConn{Conn: conn, callback: callback}
}

func (c *firstWriteSageCallbackConn) Write(payload []byte) (int, error) {
	positive := len(payload) > 0
	if positive {
		c.beginWriteAttempt()
	}
	n, err := c.Conn.Write(payload)
	if positive {
		result := err
		if n > 0 {
			result = nil
		}
		c.finishWriteAttempt(n > 0 || err != nil, result)
	}
	return n, err
}

func (c *firstWriteSageCallbackConn) WriteBuffer(buffer *buf.Buffer) error {
	n := buffer.Len()
	if n > 0 {
		c.beginWriteAttempt()
	}
	err := c.Conn.WriteBuffer(buffer)
	if n > 0 {
		c.finishWriteAttempt(true, err)
	}
	return err
}

func (c *firstWriteSageCallbackConn) Close() error {
	settle := false
	c.mu.Lock()
	if !c.decisionMade {
		if c.pending == 0 {
			c.decisionMade = true
			settle = true
		} else {
			c.closePending = true
		}
	}
	c.mu.Unlock()
	if settle {
		c.settle(net.ErrClosed)
	}
	return c.Conn.Close()
}

func (c *firstWriteSageCallbackConn) Upstream() any { return c.Conn }
func (c *firstWriteSageCallbackConn) ReaderReplaceable() bool {
	return true
}
func (c *firstWriteSageCallbackConn) WriterReplaceable() bool {
	return c.settled.Load()
}
func (c *firstWriteSageCallbackConn) WriterPossiblyReplaceable() bool {
	return !c.settled.Load()
}

func (c *firstWriteSageCallbackConn) settle(err error) {
	c.once.Do(func() {
		c.settled.Store(true)
		c.callback(err)
	})
}

func (c *firstWriteSageCallbackConn) beginWriteAttempt() {
	c.mu.Lock()
	c.pending++
	c.mu.Unlock()
}

func (c *firstWriteSageCallbackConn) finishWriteAttempt(decisive bool, result error) {
	settle := false
	c.mu.Lock()
	if c.pending > 0 {
		c.pending--
	}
	if !c.decisionMade {
		if decisive {
			c.decisionMade = true
			settle = true
		} else if c.pending == 0 && c.closePending {
			c.decisionMade = true
			settle = true
			result = net.ErrClosed
		}
	}
	c.mu.Unlock()
	if settle {
		c.settle(result)
	}
}

// sageObservedConn observes application-visible bytes without changing
// connection ownership. The caller remains responsible for closing the
// underlying connection.
type sageObservedConn struct {
	C.Conn
	clock          sageClock
	onResponse     func(time.Duration)
	onThroughput   func(float64)
	onWindow       func(sageThroughputObservation) sagePolicyAction
	onClose        func(sageConnectionCloseObservation)
	onNativeClose  func(sageConnectionCloseObservation)
	onNativeWindow func(sageThroughputObservation, string)

	mu               sync.Mutex
	createdAt        time.Time
	firstWriteAt     time.Time
	pendingWrites    int
	provisionalRead  time.Time
	wrotePayload     bool
	responseRecorded bool
	segmentStart     time.Time
	segmentLastRead  time.Time
	segmentBytes     int64
	totalReadBytes   int64
	closing          bool
	policyClosed     bool
	relayDepth       int
	closePending     bool
	closedAt         time.Time
	lifecycleMu      sync.Mutex
	lifecycle        sageConnectionLifecycle
	closeOnce        sync.Once
	closeObserveOnce sync.Once
	nativeCloseOnce  sync.Once
	closeErr         error
}

type sagePolicyAction func() bool

type sageConnectionLifecycle uint8

const (
	sageConnectionOpen sageConnectionLifecycle = iota
	sageConnectionNaturalClosing
	sageConnectionPolicyClosing
	sageConnectionClosed
)

type sageThroughputObservation struct {
	BitsPerSecond float64
	Bytes         int64
	Duration      time.Duration
	TotalBytes    int64
	Age           time.Duration
}

// sageConnectionCloseObservation describes only locally observable
// connection facts. It deliberately does not claim why the flow ended.
type sageConnectionCloseObservation struct {
	WrotePayload   bool
	TotalReadBytes int64
	Age            time.Duration
	PolicyClosed   bool
}

func newSageObservedConn(conn C.Conn, clock sageClock, onResponse func(time.Duration), onThroughput func(float64)) C.Conn {
	return newSageControlledConn(conn, clock, onResponse, onThroughput, nil)
}

func newSageControlledConn(conn C.Conn, clock sageClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(sageThroughputObservation) sagePolicyAction) C.Conn {
	return newSageControlledConnWithClose(conn, clock, onResponse, onThroughput, onWindow, nil)
}

func newSageControlledConnWithClose(conn C.Conn, clock sageClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(sageThroughputObservation) sagePolicyAction, onClose func(sageConnectionCloseObservation)) C.Conn {
	return newSageControlledConnWithNative(conn, clock, onResponse, onThroughput, onWindow, onClose, nil, nil)
}

func newSageControlledConnWithNative(conn C.Conn, clock sageClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(sageThroughputObservation) sagePolicyAction, onClose func(sageConnectionCloseObservation), onNativeClose func(sageConnectionCloseObservation), onNativeWindow func(sageThroughputObservation, string)) C.Conn {
	if clock == nil {
		clock = sageSystemClock{}
	}
	now := clock.Now()
	return &sageObservedConn{
		Conn:           conn,
		clock:          clock,
		onResponse:     onResponse,
		onThroughput:   onThroughput,
		onWindow:       onWindow,
		onClose:        onClose,
		onNativeClose:  onNativeClose,
		onNativeWindow: onNativeWindow,
		createdAt:      now,
	}
}

func (c *sageObservedConn) Write(payload []byte) (int, error) {
	if len(payload) > 0 {
		c.beginWrite()
	}
	n, err := c.Conn.Write(payload)
	if len(payload) > 0 {
		c.finishWrite(c.clock.Now(), n > 0)
	}
	return n, err
}

func (c *sageObservedConn) WriteBuffer(buffer *buf.Buffer) error {
	payload := buffer.Len()
	if payload > 0 {
		c.beginWrite()
	}
	err := c.Conn.WriteBuffer(buffer)
	if payload > 0 {
		c.finishWrite(c.clock.Now(), err == nil)
	}
	return err
}

func (c *sageObservedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return &sageObservedWriter{owner: c, writer: c.Conn}, []N.CountFunc{func(written int64) {
		if written > 0 {
			c.observeWrite(c.clock.Now())
		}
	}}
}

type sageObservedWriter struct {
	owner  *sageObservedConn
	writer io.Writer
}

func (w *sageObservedWriter) Write(payload []byte) (int, error) {
	if len(payload) > 0 {
		w.owner.beginWrite()
	}
	n, err := w.writer.Write(payload)
	if len(payload) > 0 {
		w.owner.finishWrite(w.owner.clock.Now(), n > 0)
	}
	return n, err
}

func (w *sageObservedWriter) Upstream() any { return w.writer }
func (w *sageObservedWriter) WriterReplaceable() bool {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	return w.owner.wrotePayload
}
func (w *sageObservedWriter) WriterPossiblyReplaceable() bool {
	return !w.WriterReplaceable()
}

func (c *sageObservedConn) Read(payload []byte) (int, error) {
	n, err := c.Conn.Read(payload)
	if n > 0 {
		c.observeRead(c.clock.Now(), int64(n), false)
	}
	return n, err
}

func (c *sageObservedConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	err := c.Conn.ReadBuffer(buffer)
	read := buffer.Len() - before
	if read > 0 {
		c.observeRead(c.clock.Now(), int64(read), false)
	}
	return err
}

func (c *sageObservedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(read int64) {
		if read > 0 {
			// sing invokes reader counters only after the positive payload has
			// reached the destination. Policy close is permitted only here;
			// direct Read and ReadBuffer must return their bytes first.
			c.observeRead(c.clock.Now(), read, true)
		}
	}}
}

func (c *sageObservedConn) Close() error {
	c.lifecycleMu.Lock()
	if c.lifecycle != sageConnectionOpen {
		c.lifecycleMu.Unlock()
		return c.closeUnderlying()
	}
	c.lifecycle = sageConnectionNaturalClosing
	c.lifecycleMu.Unlock()
	closedAt := c.clock.Now()

	c.mu.Lock()
	c.closing = true
	segmentStart, segmentEnd, segmentBytes := c.segmentStart, c.segmentLastRead, c.segmentBytes
	sample, ok := c.finishSegmentLocked()
	var nativeObservation sageThroughputObservation
	if ok {
		nativeObservation = c.throughputObservationLocked(sample, segmentStart, segmentEnd, segmentBytes, closedAt)
	}
	c.mu.Unlock()
	if ok && c.onThroughput != nil {
		c.onThroughput(sample)
	}
	if ok && c.onNativeWindow != nil {
		c.onNativeWindow(nativeObservation, "close")
	}
	err := c.closeUnderlying()
	c.lifecycleMu.Lock()
	c.lifecycle = sageConnectionClosed
	c.lifecycleMu.Unlock()
	if observation, ready := c.closeObservation(closedAt); ready {
		c.emitCloseObservation(observation)
	}
	return err
}

// RelayStarted and RelayFinished are a read-only lifecycle fence used by
// common/net.Relay. An early close from one copy direction must not freeze a
// low byte count while the opposite direction still has delivered-byte
// counters in flight.
func (c *sageObservedConn) RelayStarted() {
	c.mu.Lock()
	c.relayDepth++
	c.mu.Unlock()
}

func (c *sageObservedConn) RelayFinished() {
	var observation sageConnectionCloseObservation
	ready := false
	c.mu.Lock()
	if c.relayDepth > 0 {
		c.relayDepth--
	}
	if c.relayDepth == 0 && c.closePending {
		observation = c.closeObservationLocked(c.closedAt)
		c.closePending = false
		ready = true
	}
	c.mu.Unlock()
	if ready {
		c.emitCloseObservation(observation)
	}
}

func (c *sageObservedConn) closeObservation(closedAt time.Time) (sageConnectionCloseObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.onClose == nil && c.onNativeClose == nil {
		return sageConnectionCloseObservation{}, false
	}
	if c.relayDepth > 0 {
		c.closePending = true
		c.closedAt = closedAt
		return sageConnectionCloseObservation{}, false
	}
	return c.closeObservationLocked(closedAt), true
}

func (c *sageObservedConn) closeObservationLocked(closedAt time.Time) sageConnectionCloseObservation {
	return sageConnectionCloseObservation{
		WrotePayload:   c.wrotePayload,
		TotalReadBytes: c.totalReadBytes,
		Age:            sageElapsed(c.createdAt, closedAt),
		PolicyClosed:   c.policyClosed,
	}
}

func (c *sageObservedConn) emitCloseObservation(observation sageConnectionCloseObservation) {
	c.closeObserveOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(observation)
		}
	})
	c.emitNativeCloseObservation(observation)
}

func (c *sageObservedConn) emitNativeCloseObservation(observation sageConnectionCloseObservation) {
	c.nativeCloseOnce.Do(func() {
		if c.onNativeClose != nil {
			c.onNativeClose(observation)
		}
	})
}

func (c *sageObservedConn) Upstream() any { return c.Conn }

func (c *sageObservedConn) observeWrite(now time.Time) {
	var response time.Duration
	var recordResponse bool
	c.mu.Lock()
	if !c.wrotePayload {
		c.wrotePayload = true
		c.firstWriteAt = now
		if !c.provisionalRead.IsZero() && !c.responseRecorded {
			c.responseRecorded = true
			response = sageElapsed(now, c.provisionalRead)
			recordResponse = true
			c.provisionalRead = time.Time{}
		}
	}
	c.mu.Unlock()
	if recordResponse && c.onResponse != nil {
		c.onResponse(response)
	}
}

func (c *sageObservedConn) beginWrite() {
	c.mu.Lock()
	c.pendingWrites++
	c.mu.Unlock()
}

func (c *sageObservedConn) finishWrite(now time.Time, success bool) {
	var response time.Duration
	var recordResponse bool
	c.mu.Lock()
	if c.pendingWrites > 0 {
		c.pendingWrites--
	}
	if success && !c.wrotePayload {
		c.wrotePayload = true
		c.firstWriteAt = now
		if !c.provisionalRead.IsZero() && !c.responseRecorded {
			c.responseRecorded = true
			response = sageElapsed(now, c.provisionalRead)
			recordResponse = true
			c.provisionalRead = time.Time{}
		}
	}
	if !c.wrotePayload && c.pendingWrites == 0 {
		c.provisionalRead = time.Time{}
	}
	c.mu.Unlock()
	if recordResponse && c.onResponse != nil {
		c.onResponse(response)
	}
}

func (c *sageObservedConn) observeRead(now time.Time, count int64, delivered bool) {
	if count <= 0 {
		return
	}

	var response time.Duration
	var recordResponse bool
	var throughput float64
	var recordThroughput bool
	var observation sageThroughputObservation
	var throughputReason string

	c.mu.Lock()
	c.totalReadBytes += count
	if c.wrotePayload && !c.responseRecorded {
		c.responseRecorded = true
		response = sageElapsed(c.firstWriteAt, now)
		recordResponse = true
	} else if !c.wrotePayload && c.pendingWrites > 0 && c.provisionalRead.IsZero() {
		c.provisionalRead = now
	}

	if c.segmentStart.IsZero() {
		c.segmentStart = now
		c.segmentLastRead = now
		c.segmentBytes = count
	} else if now.Sub(c.segmentLastRead) > sageThroughputGap {
		throughput, recordThroughput = sageThroughputSample(c.segmentStart, c.segmentLastRead, c.segmentBytes)
		if recordThroughput {
			observation = c.throughputObservationLocked(throughput, c.segmentStart, c.segmentLastRead, c.segmentBytes, now)
			throughputReason = "gap"
		}
		c.segmentStart = now
		c.segmentLastRead = now
		c.segmentBytes = count
	} else {
		c.segmentLastRead = now
		c.segmentBytes += count
	}

	if now.Sub(c.segmentStart) >= sageThroughputWindow {
		throughput, recordThroughput = sageThroughputSample(c.segmentStart, now, c.segmentBytes)
		if recordThroughput {
			observation = c.throughputObservationLocked(throughput, c.segmentStart, now, c.segmentBytes, now)
			throughputReason = "window"
		}
		c.clearSegmentLocked()
	} else if c.closing {
		segmentStart, segmentEnd, segmentBytes := c.segmentStart, c.segmentLastRead, c.segmentBytes
		if closingSample, ok := c.finishSegmentLocked(); ok {
			throughput, recordThroughput = closingSample, true
			observation = c.throughputObservationLocked(throughput, segmentStart, segmentEnd, segmentBytes, now)
			throughputReason = "close"
		}
	}
	c.mu.Unlock()

	if recordResponse && c.onResponse != nil {
		c.onResponse(response)
	}
	if recordThroughput && c.onThroughput != nil {
		c.onThroughput(throughput)
	}
	if recordThroughput && c.onNativeWindow != nil {
		c.onNativeWindow(observation, throughputReason)
	}
	if delivered && recordThroughput && c.onWindow != nil {
		if action := c.onWindow(observation); action != nil {
			c.requestAbort(action)
		}
	}
}

func (c *sageObservedConn) throughputObservationLocked(bitsPerSecond float64, start, end time.Time, bytes int64, now time.Time) sageThroughputObservation {
	return sageThroughputObservation{
		BitsPerSecond: bitsPerSecond,
		Bytes:         bytes,
		Duration:      sageElapsed(start, end),
		TotalBytes:    c.totalReadBytes,
		Age:           sageElapsed(c.createdAt, now),
	}
}

func (c *sageObservedConn) requestAbort(action sagePolicyAction) {
	if action == nil {
		return
	}
	c.lifecycleMu.Lock()
	if c.lifecycle != sageConnectionOpen {
		c.lifecycleMu.Unlock()
		return
	}
	c.lifecycle = sageConnectionPolicyClosing
	if !action() {
		c.lifecycle = sageConnectionOpen
		c.lifecycleMu.Unlock()
		return
	}
	c.lifecycleMu.Unlock()

	closedAt := c.clock.Now()
	c.mu.Lock()
	c.closing = true
	c.policyClosed = true
	segmentStart, segmentEnd, segmentBytes := c.segmentStart, c.segmentLastRead, c.segmentBytes
	sample, ok := c.finishSegmentLocked()
	var nativeObservation sageThroughputObservation
	if ok {
		nativeObservation = c.throughputObservationLocked(sample, segmentStart, segmentEnd, segmentBytes, closedAt)
	}
	c.mu.Unlock()
	if ok && c.onThroughput != nil {
		c.onThroughput(sample)
	}
	if ok && c.onNativeWindow != nil {
		c.onNativeWindow(nativeObservation, "policy_close")
	}
	_ = c.closeUnderlying()
	c.lifecycleMu.Lock()
	c.lifecycle = sageConnectionClosed
	c.lifecycleMu.Unlock()
	if observation, ready := c.closeObservation(closedAt); ready {
		c.emitNativeCloseObservation(observation)
	}
}

func (c *sageObservedConn) closeUnderlying() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *sageObservedConn) finishSegmentLocked() (float64, bool) {
	sample, ok := sageThroughputSample(c.segmentStart, c.segmentLastRead, c.segmentBytes)
	if !ok {
		// Keep an incomplete tail while Close releases a concurrent read. The
		// late positive read can make the same active segment eligible and will
		// settle it because closing is already visible under this mutex.
		return 0, false
	}
	c.clearSegmentLocked()
	return sample, true
}

func (c *sageObservedConn) clearSegmentLocked() {
	c.segmentStart = time.Time{}
	c.segmentLastRead = time.Time{}
	c.segmentBytes = 0
}

func sageThroughputSample(start, end time.Time, bytes int64) (float64, bool) {
	if start.IsZero() || end.Before(start) || bytes < sageThroughputMinPayload {
		return 0, false
	}
	duration := end.Sub(start)
	if duration < sageThroughputMinWindow {
		return 0, false
	}
	return 8 * float64(bytes) / duration.Seconds(), true
}

// firstPacketWriteSageCallbackConn waits for the first positive UDP
// datagram. Creating a PacketConn alone is not evidence that the path can send.
type firstPacketWriteSageCallbackConn struct {
	C.PacketConn
	once      sync.Once
	settled   atomic.Bool
	callback  func(error)
	onClose   func()
	closeOnce sync.Once

	mu           sync.Mutex
	pending      int
	responseSeen bool
	firstErr     error
	closePending bool
	decisionMade bool
}

func newFirstPacketWriteSageCallbackConn(packetConn C.PacketConn, callback func(error)) C.PacketConn {
	return newFirstPacketWriteSageCallbackConnWithClose(packetConn, callback, nil)
}

func newFirstPacketWriteSageCallbackConnWithClose(packetConn C.PacketConn, callback func(error), onClose func()) C.PacketConn {
	return &firstPacketWriteSageCallbackConn{PacketConn: packetConn, callback: callback, onClose: onClose}
}

func (c *firstPacketWriteSageCallbackConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	positive := len(payload) > 0
	if positive {
		c.mu.Lock()
		c.pending++
		c.mu.Unlock()
	}
	n, err := c.PacketConn.WriteTo(payload, address)
	if positive {
		c.finishWrite(n > 0 && err == nil, err)
	}
	return n, err
}

func (c *firstPacketWriteSageCallbackConn) Close() error {
	settle := false
	c.mu.Lock()
	if !c.decisionMade {
		if c.pending == 0 {
			c.decisionMade = true
			settle = true
		} else {
			c.closePending = true
		}
	}
	c.mu.Unlock()
	if settle {
		c.settle(net.ErrClosed)
	}
	err := c.PacketConn.Close()
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

func (c *firstPacketWriteSageCallbackConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(payload)
	if n > 0 {
		c.observeResponse()
	}
	return n, address, err
}

func (c *firstPacketWriteSageCallbackConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	payload, put, address, err := c.PacketConn.WaitReadFrom()
	if len(payload) > 0 {
		c.observeResponse()
	}
	return payload, put, address, err
}

func (c *firstPacketWriteSageCallbackConn) Upstream() any { return c.PacketConn }
func (c *firstPacketWriteSageCallbackConn) ReaderReplaceable() bool {
	return c.settled.Load()
}
func (c *firstPacketWriteSageCallbackConn) WriterReplaceable() bool {
	return c.settled.Load()
}
func (c *firstPacketWriteSageCallbackConn) ReaderPossiblyReplaceable() bool {
	return !c.settled.Load()
}
func (c *firstPacketWriteSageCallbackConn) WriterPossiblyReplaceable() bool {
	return !c.settled.Load()
}

func (c *firstPacketWriteSageCallbackConn) observeResponse() {
	c.mu.Lock()
	if c.pending > 0 && !c.settled.Load() {
		c.responseSeen = true
	}
	c.mu.Unlock()
}

func (c *firstPacketWriteSageCallbackConn) finishWrite(success bool, err error) {
	var settle bool
	var result error
	c.mu.Lock()
	if c.pending > 0 {
		c.pending--
	}
	if err != nil && c.firstErr == nil {
		c.firstErr = err
	}
	if !c.decisionMade {
		if c.responseSeen || success {
			c.decisionMade = true
			settle = true
		} else if c.pending == 0 && c.firstErr != nil {
			c.decisionMade = true
			settle = true
			result = c.firstErr
		} else if c.pending == 0 && c.closePending {
			c.decisionMade = true
			settle = true
			result = net.ErrClosed
		}
	}
	c.mu.Unlock()
	if settle {
		c.settle(result)
	}
}

func (c *firstPacketWriteSageCallbackConn) settle(err error) {
	c.once.Do(func() {
		c.settled.Store(true)
		c.callback(err)
	})
}
