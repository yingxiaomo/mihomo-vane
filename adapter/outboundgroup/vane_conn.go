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
	vaneThroughputGap        = 2 * time.Second
	vaneThroughputWindow     = 5 * time.Second
	vaneThroughputMinWindow  = 2 * time.Second
	vaneThroughputMinPayload = 64 * 1024
)

// firstWriteVaneCallbackConn settles a deferred handshake exactly once on
// the first non-empty write attempt. Zero-length writes carry no evidence.
type firstWriteVaneCallbackConn struct {
	C.Conn
	once     sync.Once
	settled  atomic.Bool
	callback func(error)

	mu           sync.Mutex
	pending      int
	closePending bool
	decisionMade bool
}

func newFirstWriteVaneCallbackConn(conn C.Conn, callback func(error)) C.Conn {
	return &firstWriteVaneCallbackConn{Conn: conn, callback: callback}
}

func (c *firstWriteVaneCallbackConn) Write(payload []byte) (int, error) {
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

func (c *firstWriteVaneCallbackConn) WriteBuffer(buffer *buf.Buffer) error {
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

func (c *firstWriteVaneCallbackConn) Close() error {
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

func (c *firstWriteVaneCallbackConn) Upstream() any { return c.Conn }
func (c *firstWriteVaneCallbackConn) ReaderReplaceable() bool {
	return true
}
func (c *firstWriteVaneCallbackConn) WriterReplaceable() bool {
	return c.settled.Load()
}
func (c *firstWriteVaneCallbackConn) WriterPossiblyReplaceable() bool {
	return !c.settled.Load()
}

func (c *firstWriteVaneCallbackConn) settle(err error) {
	c.once.Do(func() {
		c.settled.Store(true)
		c.callback(err)
	})
}

func (c *firstWriteVaneCallbackConn) beginWriteAttempt() {
	c.mu.Lock()
	c.pending++
	c.mu.Unlock()
}

func (c *firstWriteVaneCallbackConn) finishWriteAttempt(decisive bool, result error) {
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

// vaneObservedConn observes application-visible bytes without changing
// connection ownership. The caller remains responsible for closing the
// underlying connection.
type vaneObservedConn struct {
	C.Conn
	clock                   vaneClock
	onResponse              func(time.Duration)
	onThroughput            func(float64)
	onWindow                func(vaneThroughputObservation) vanePolicyAction
	onClose                 func(vaneConnectionCloseObservation)
	onNativeClose           func(vaneConnectionCloseObservation)
	onNativeWindow          func(vaneThroughputObservation, string)
	onNaturalCloseOwnership func()

	mu               sync.Mutex
	createdAt        time.Time
	firstWriteAt     time.Time
	pendingWrites    int
	provisionalRead  time.Time
	wrotePayload     bool
	responseRecorded bool
	responseBytes    int64
	responseAt       time.Time
	segmentStart     time.Time
	segmentLastRead  time.Time
	segmentBytes     int64
	totalReadBytes   int64
	closing          bool
	policyClosed     bool
	relayDepth       int
	closePending     bool
	closedAt         time.Time
	b2Stats          *vaneTCPStats
	lifecycleMu      sync.Mutex
	lifecycle        vaneConnectionLifecycle
	closeOnce        sync.Once
	closeObserveOnce sync.Once
	nativeCloseOnce  sync.Once
	closeErr         error
	directPolicy     bool
	// shadowObserve lets the window policy run on undelivered windows
	// while racing is in shadow mode, purely to observe: the policy runs so
	// low windows accumulate and races get scheduled, but the action it
	// returns is discarded, never queued and never executed, so shadow
	// records would-handoff without changing any traffic. Without it, shadow
	// can only observe delivered windows, and a flow that mostly reads
	// directly never reaches the policy at all — the shadow deadlock
	// (SHADOW-OBSERVE-001).
	shadowObserve bool
	pendingAction vanePolicyAction
}

type vanePolicyAction func() bool

type vaneConnectionLifecycle uint8

const (
	vaneConnectionOpen vaneConnectionLifecycle = iota
	vaneConnectionNaturalClosing
	vaneConnectionPolicyClosing
	vaneConnectionClosed
)

type vaneThroughputObservation struct {
	BitsPerSecond float64
	Bytes         int64
	Duration      time.Duration
	TotalBytes    int64
	Age           time.Duration
	Delivered     bool
}

// vaneConnectionCloseObservation describes only locally observable
// connection facts. It deliberately does not claim why the flow ended.
type vaneConnectionCloseObservation struct {
	WrotePayload   bool
	TotalReadBytes int64
	Age            time.Duration
	PolicyClosed   bool
	// B2 observation (round5 item 2): the socket's cumulative loss ratio read
	// just before the underlying close. An unsupported read carries
	// LossSupported=false and must never be mistaken for zero loss.
	LossRate      float64
	LossSupported bool
	// B2 observation (round5 item 3): the first-response snapshot, taken at
	// whichever write/read site recorded the response first. Zero bytes read
	// after that point plus a long quiet tail is the header-stall signature.
	ResponseRecorded bool
	ResponseBytes    int64
	ResponseAt       time.Time
}

func newVaneObservedConn(conn C.Conn, clock vaneClock, onResponse func(time.Duration), onThroughput func(float64)) C.Conn {
	return newVaneControlledConn(conn, clock, onResponse, onThroughput, nil)
}

func newVaneControlledConn(conn C.Conn, clock vaneClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(vaneThroughputObservation) vanePolicyAction) C.Conn {
	return newVaneControlledConnWithClose(conn, clock, onResponse, onThroughput, onWindow, nil)
}

func newVaneControlledConnWithClose(conn C.Conn, clock vaneClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(vaneThroughputObservation) vanePolicyAction, onClose func(vaneConnectionCloseObservation)) C.Conn {
	return newVaneControlledConnWithNative(conn, clock, onResponse, onThroughput, onWindow, onClose, nil, nil, nil)
}

func newVaneControlledConnWithNative(conn C.Conn, clock vaneClock, onResponse func(time.Duration), onThroughput func(float64), onWindow func(vaneThroughputObservation) vanePolicyAction, onClose func(vaneConnectionCloseObservation), onNativeClose func(vaneConnectionCloseObservation), onNativeWindow func(vaneThroughputObservation, string), onNaturalCloseOwnership func()) C.Conn {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	now := clock.Now()
	return &vaneObservedConn{
		Conn:                    conn,
		clock:                   clock,
		onResponse:              onResponse,
		onThroughput:            onThroughput,
		onWindow:                onWindow,
		onClose:                 onClose,
		onNativeClose:           onNativeClose,
		onNativeWindow:          onNativeWindow,
		onNaturalCloseOwnership: onNaturalCloseOwnership,
		createdAt:               now,
	}
}

func (c *vaneObservedConn) Write(payload []byte) (int, error) {
	c.drainPendingAbort()
	if len(payload) > 0 {
		c.beginWrite()
	}
	n, err := c.Conn.Write(payload)
	if len(payload) > 0 {
		c.finishWrite(c.clock.Now(), n > 0)
	}
	return n, err
}

func (c *vaneObservedConn) WriteBuffer(buffer *buf.Buffer) error {
	c.drainPendingAbort()
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

func (c *vaneObservedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return &vaneObservedWriter{owner: c, writer: c.Conn}, []N.CountFunc{func(written int64) {
		if written > 0 {
			c.observeWrite(c.clock.Now())
		}
	}}
}

type vaneObservedWriter struct {
	owner  *vaneObservedConn
	writer io.Writer
}

func (w *vaneObservedWriter) Write(payload []byte) (int, error) {
	if len(payload) > 0 {
		w.owner.beginWrite()
	}
	n, err := w.writer.Write(payload)
	if len(payload) > 0 {
		w.owner.finishWrite(w.owner.clock.Now(), n > 0)
	}
	return n, err
}

func (w *vaneObservedWriter) Upstream() any { return w.writer }
func (w *vaneObservedWriter) WriterReplaceable() bool {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	return w.owner.wrotePayload
}
func (w *vaneObservedWriter) WriterPossiblyReplaceable() bool {
	return !w.WriterReplaceable()
}

func (c *vaneObservedConn) Read(payload []byte) (int, error) {
	c.drainPendingAbort()
	n, err := c.Conn.Read(payload)
	if n > 0 {
		c.observeRead(c.clock.Now(), int64(n), false)
	}
	return n, err
}

func (c *vaneObservedConn) ReadBuffer(buffer *buf.Buffer) error {
	c.drainPendingAbort()
	before := buffer.Len()
	err := c.Conn.ReadBuffer(buffer)
	read := buffer.Len() - before
	if read > 0 {
		c.observeRead(c.clock.Now(), int64(read), false)
	}
	return err
}

func (c *vaneObservedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(read int64) {
		if read > 0 {
			// sing invokes reader counters only after the positive payload has
			// reached the destination. Policy close is permitted only here;
			// direct Read and ReadBuffer must return their bytes first.
			c.observeRead(c.clock.Now(), read, true)
		}
	}}
}

func (c *vaneObservedConn) Close() error {
	c.lifecycleMu.Lock()
	if c.lifecycle != vaneConnectionOpen {
		c.lifecycleMu.Unlock()
		return c.closeUnderlying()
	}
	c.lifecycle = vaneConnectionNaturalClosing
	if c.onNaturalCloseOwnership != nil {
		// Ownership is claimed here, under lifecycleMu, before any queued
		// policy action can run. The callback only takes the flow lock, which
		// keeps the lifecycleMu -> flow.mu order used by requestAbort.
		c.onNaturalCloseOwnership()
	}
	c.lifecycleMu.Unlock()
	closedAt := c.clock.Now()

	c.mu.Lock()
	c.closing = true
	segmentStart, segmentEnd, segmentBytes := c.segmentStart, c.segmentLastRead, c.segmentBytes
	sample, ok := c.finishSegmentLocked()
	var nativeObservation vaneThroughputObservation
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
	c.lifecycle = vaneConnectionClosed
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
func (c *vaneObservedConn) RelayStarted() {
	c.mu.Lock()
	c.relayDepth++
	c.mu.Unlock()
}

func (c *vaneObservedConn) RelayFinished() {
	var observation vaneConnectionCloseObservation
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

func (c *vaneObservedConn) closeObservation(closedAt time.Time) (vaneConnectionCloseObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.onClose == nil && c.onNativeClose == nil {
		return vaneConnectionCloseObservation{}, false
	}
	if c.relayDepth > 0 {
		c.closePending = true
		c.closedAt = closedAt
		return vaneConnectionCloseObservation{}, false
	}
	return c.closeObservationLocked(closedAt), true
}

func (c *vaneObservedConn) closeObservationLocked(closedAt time.Time) vaneConnectionCloseObservation {
	observation := vaneConnectionCloseObservation{
		WrotePayload:   c.wrotePayload,
		TotalReadBytes: c.totalReadBytes,
		Age:            vaneElapsed(c.createdAt, closedAt),
		PolicyClosed:   c.policyClosed,
	}
	observation.LossRate, observation.LossSupported = c.b2Stats.lossRate()
	observation.ResponseRecorded = c.responseRecorded
	observation.ResponseBytes = c.responseBytes
	observation.ResponseAt = c.responseAt
	return observation
}

func (c *vaneObservedConn) emitCloseObservation(observation vaneConnectionCloseObservation) {
	c.closeObserveOnce.Do(func() {
		if c.onClose != nil {
			c.onClose(observation)
		}
	})
	c.emitNativeCloseObservation(observation)
}

func (c *vaneObservedConn) emitNativeCloseObservation(observation vaneConnectionCloseObservation) {
	c.nativeCloseOnce.Do(func() {
		if c.onNativeClose != nil {
			c.onNativeClose(observation)
		}
	})
}

func (c *vaneObservedConn) Upstream() any { return c.Conn }

func (c *vaneObservedConn) observeWrite(now time.Time) {
	c.mu.Lock()
	if !c.wrotePayload {
		c.wrotePayload = true
		c.firstWriteAt = now
		if !c.provisionalRead.IsZero() && !c.responseRecorded {
			// The read arrived before the write completed, so there is no
			// measurable request->response duration. Keep the accounting for
			// B2 stall detection, but emit no response sample.
			c.responseRecorded = true
			c.responseBytes = c.totalReadBytes
			c.responseAt = now
			c.provisionalRead = time.Time{}
		}
	}
	c.mu.Unlock()
}

func (c *vaneObservedConn) beginWrite() {
	c.mu.Lock()
	c.pendingWrites++
	c.mu.Unlock()
}

func (c *vaneObservedConn) finishWrite(now time.Time, success bool) {
	c.mu.Lock()
	if c.pendingWrites > 0 {
		c.pendingWrites--
	}
	if success && !c.wrotePayload {
		c.wrotePayload = true
		c.firstWriteAt = now
		if !c.provisionalRead.IsZero() && !c.responseRecorded {
			// The read preceded send confirmation: account it for B2, but do
			// not turn it into a zero-millisecond response sample.
			c.responseRecorded = true
			c.responseBytes = c.totalReadBytes
			c.responseAt = now
			c.provisionalRead = time.Time{}
		}
	}
	if !c.wrotePayload && c.pendingWrites == 0 {
		c.provisionalRead = time.Time{}
	}
	c.mu.Unlock()
}

func (c *vaneObservedConn) observeRead(now time.Time, count int64, delivered bool) {
	if count <= 0 {
		return
	}

	var response time.Duration
	var recordResponse bool
	var throughput float64
	var recordThroughput bool
	var observation vaneThroughputObservation
	var throughputReason string

	c.mu.Lock()
	c.totalReadBytes += count
	if c.wrotePayload && !c.responseRecorded {
		c.responseRecorded = true
		c.responseBytes = c.totalReadBytes
		c.responseAt = now
		response = vaneElapsed(c.firstWriteAt, now)
		recordResponse = true
	} else if !c.wrotePayload && c.pendingWrites > 0 && c.provisionalRead.IsZero() {
		c.provisionalRead = now
	}

	if c.segmentStart.IsZero() {
		c.segmentStart = now
		c.segmentLastRead = now
		c.segmentBytes = count
	} else if now.Sub(c.segmentLastRead) > vaneThroughputGap {
		throughput, recordThroughput = vaneThroughputSample(c.segmentStart, c.segmentLastRead, c.segmentBytes)
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

	if now.Sub(c.segmentStart) >= vaneThroughputWindow {
		throughput, recordThroughput = vaneThroughputSample(c.segmentStart, now, c.segmentBytes)
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
	if recordThroughput && c.onWindow != nil {
		c.mu.Lock()
		directPolicy := c.directPolicy
		shadowObserve := c.shadowObserve
		c.mu.Unlock()
		if delivered || directPolicy || shadowObserve {
			observation.Delivered = delivered
			if action := c.onWindow(observation); action != nil {
				if shadowObserve && !delivered && !directPolicy {
					// Shadow observes only: the race was already scheduled
					// inside the policy, and would-handoff is recorded by
					// the race callback. Discarding the baseline action
					// keeps shadow from changing any traffic.
				} else if delivered {
					c.requestAbort(action)
				} else {
					c.mu.Lock()
					if c.pendingAction == nil {
						c.pendingAction = action
					}
					c.mu.Unlock()
				}
			}
		}
	}
}

func (c *vaneObservedConn) enableDirectPolicy() {
	c.mu.Lock()
	c.directPolicy = true
	c.mu.Unlock()
}

// enableShadowObserve lets the window policy run on undelivered windows
// while racing is in shadow mode, purely to observe. The policy runs so low
// windows accumulate and races get scheduled, but the action it returns is
// discarded at the gate, never queued and never executed. Without it, shadow
// can only observe delivered windows, and a flow that mostly reads directly
// never reaches the policy at all — the shadow deadlock (SHADOW-OBSERVE-001).
func (c *vaneObservedConn) enableShadowObserve() {
	c.mu.Lock()
	c.shadowObserve = true
	c.mu.Unlock()
}

func (c *vaneObservedConn) submitPolicyAction(action vanePolicyAction, delivered bool) {
	if delivered {
		c.requestAbort(action)
		return
	}
	c.mu.Lock()
	if c.pendingAction == nil {
		c.pendingAction = action
	}
	c.mu.Unlock()
}

func (c *vaneObservedConn) drainPendingAbort() {
	c.mu.Lock()
	action := c.pendingAction
	c.pendingAction = nil
	c.mu.Unlock()
	if action != nil {
		c.requestAbort(action)
	}
}

func (c *vaneObservedConn) throughputObservationLocked(bitsPerSecond float64, start, end time.Time, bytes int64, now time.Time) vaneThroughputObservation {
	return vaneThroughputObservation{
		BitsPerSecond: bitsPerSecond,
		Bytes:         bytes,
		Duration:      vaneElapsed(start, end),
		TotalBytes:    c.totalReadBytes,
		Age:           vaneElapsed(c.createdAt, now),
	}
}

func (c *vaneObservedConn) requestAbort(action vanePolicyAction) {
	if action == nil {
		return
	}
	c.lifecycleMu.Lock()
	if c.lifecycle != vaneConnectionOpen {
		c.lifecycleMu.Unlock()
		return
	}
	c.lifecycle = vaneConnectionPolicyClosing
	if !action() {
		c.lifecycle = vaneConnectionOpen
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
	var nativeObservation vaneThroughputObservation
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
	c.lifecycle = vaneConnectionClosed
	c.lifecycleMu.Unlock()
	if observation, ready := c.closeObservation(closedAt); ready {
		c.emitNativeCloseObservation(observation)
	}
}

func (c *vaneObservedConn) closeUnderlying() error {
	c.closeOnce.Do(func() {
		// B2 item 2: the kernel counters die with the socket — read them
		// before Close. The read runs outside the selector lock; unsupported
		// platforms simply get nil, which the observation carries as
		// "unsupported", never as zero loss.
		stats := vaneReadTCPStats(c.Conn)
		c.mu.Lock()
		c.b2Stats = stats
		c.mu.Unlock()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *vaneObservedConn) finishSegmentLocked() (float64, bool) {
	sample, ok := vaneThroughputSample(c.segmentStart, c.segmentLastRead, c.segmentBytes)
	if !ok {
		// Keep an incomplete tail while Close releases a concurrent read. The
		// late positive read can make the same active segment eligible and will
		// settle it because closing is already visible under this mutex.
		return 0, false
	}
	c.clearSegmentLocked()
	return sample, true
}

func (c *vaneObservedConn) clearSegmentLocked() {
	c.segmentStart = time.Time{}
	c.segmentLastRead = time.Time{}
	c.segmentBytes = 0
}

func vaneThroughputSample(start, end time.Time, bytes int64) (float64, bool) {
	if start.IsZero() || end.Before(start) || bytes < vaneThroughputMinPayload {
		return 0, false
	}
	duration := end.Sub(start)
	if duration < vaneThroughputMinWindow {
		return 0, false
	}
	return 8 * float64(bytes) / duration.Seconds(), true
}

// firstPacketWriteVaneCallbackConn waits for the first positive UDP
// datagram. Creating a PacketConn alone is not evidence that the path can send.
type firstPacketWriteVaneCallbackConn struct {
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

func newFirstPacketWriteVaneCallbackConn(packetConn C.PacketConn, callback func(error)) C.PacketConn {
	return newFirstPacketWriteVaneCallbackConnWithClose(packetConn, callback, nil)
}

func newFirstPacketWriteVaneCallbackConnWithClose(packetConn C.PacketConn, callback func(error), onClose func()) C.PacketConn {
	return &firstPacketWriteVaneCallbackConn{PacketConn: packetConn, callback: callback, onClose: onClose}
}

func (c *firstPacketWriteVaneCallbackConn) WriteTo(payload []byte, address net.Addr) (int, error) {
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

func (c *firstPacketWriteVaneCallbackConn) Close() error {
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

func (c *firstPacketWriteVaneCallbackConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(payload)
	if n > 0 {
		c.observeResponse()
	}
	return n, address, err
}

func (c *firstPacketWriteVaneCallbackConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	payload, put, address, err := c.PacketConn.WaitReadFrom()
	if len(payload) > 0 {
		c.observeResponse()
	}
	return payload, put, address, err
}

func (c *firstPacketWriteVaneCallbackConn) Upstream() any { return c.PacketConn }
func (c *firstPacketWriteVaneCallbackConn) ReaderReplaceable() bool {
	return c.settled.Load()
}
func (c *firstPacketWriteVaneCallbackConn) WriterReplaceable() bool {
	return c.settled.Load()
}
func (c *firstPacketWriteVaneCallbackConn) ReaderPossiblyReplaceable() bool {
	return !c.settled.Load()
}
func (c *firstPacketWriteVaneCallbackConn) WriterPossiblyReplaceable() bool {
	return !c.settled.Load()
}

func (c *firstPacketWriteVaneCallbackConn) observeResponse() {
	c.mu.Lock()
	if c.pending > 0 && !c.settled.Load() {
		c.responseSeen = true
	}
	c.mu.Unlock()
}

func (c *firstPacketWriteVaneCallbackConn) finishWrite(success bool, err error) {
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

func (c *firstPacketWriteVaneCallbackConn) settle(err error) {
	c.once.Do(func() {
		c.settled.Store(true)
		c.callback(err)
	})
}
