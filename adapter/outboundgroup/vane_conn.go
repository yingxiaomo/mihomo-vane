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
	vaneThroughputGap    = 2 * time.Second
	vaneThroughputWindow = 5 * time.Second
	// §F: the sample gate, halved (64KB/2s → 32KB/1s) so short and small
	// transfers still produce evidence. Paced, not calibrated; the trigger
	// gates (3 low windows / 15s / 2MiB) and the close bar are untouched.
	vaneThroughputMinWindow  = 1 * time.Second
	vaneThroughputMinPayload = 32 * 1024
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
	// §E: fired when a settled 5-second window produced no qualified sample;
	// wired to the flow's valve counter. Registered post-construction.
	onEmptyWindow func()

	mu        sync.Mutex
	createdAt time.Time
	// LAST-READ: the wall time of the last non-zero read, updated on every
	// read (not only on a qualified 5-second sample). The flow watchdog needs
	// it to tell "no data arrived" from "data trickled in below the sample
	// payload floor"; aging on the last sample instead made every low-bitrate
	// stream look stalled.
	lastReadAt       time.Time
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
	// §6 backlog: readBytes is fed by the counting reader UnwrapReader hands
	// to sing; deliveredBytes only by the post-write CountFunc. Pending
	// backlog is bytes that reached the proxy but not the client, i.e. the
	// client is the bottleneck, not the node.
	readBytes        int64
	deliveredBytes   int64
	closing          bool
	policyClosed     bool
	relayDepth       int
	closePending     bool
	closedAt         time.Time
	tcpStats         *vaneTCPStats
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
	untrusted     bool
	// B-part window health, read fresh from TCP_INFO at window build. An
	// unsupported read stays false and must never be read as a healthy zero.
	LossRate         float64
	LossSupported    bool
	Latency          time.Duration
	LatencySupported bool
	// synthetic marks a window the watchdog invented for a stalled flow, not one
	// the connection measured.
	synthetic bool
	// silence is the time since the last byte (or connection start when no
	// byte arrived), not the connection's lifetime in Age.
	silence time.Duration
}

// vaneConnectionCloseObservation describes only locally observable
// connection facts. It deliberately does not claim why the flow ended.
type vaneConnectionCloseObservation struct {
	WrotePayload   bool
	TotalReadBytes int64
	Age            time.Duration
	PolicyClosed   bool
	// The socket's cumulative loss ratio is read
	// just before the underlying close. An unsupported read carries
	// LossSupported=false and must never be mistaken for zero loss.
	LossRate      float64
	LossSupported bool
	// B.3: the raw counters behind LossRate, so the group can accumulate a
	// node-level cumulative loss ratio. Zero means the kernel reported none.
	SegsOut     uint64
	RetransSegs uint64
	// The first-response snapshot is taken at
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
	// P2 (audit 2026-11-22): drain like the conn's own Write — a flow whose
	// reads queue its policy action but whose writes go through this
	// unwrapped writer would otherwise never execute the queued close.
	w.owner.drainPendingAbort()
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

// vaneCountReader counts bytes as sing reads them off the node. It must stay
// a bare io.Reader: implementing ReadBuffer, UnwrapReader/ReadCounter,
// Upstream/ReaderReplaceable or syscall.Conn would let sing skip or unwrap
// the counting, and the backlog signal would silently stay zero.
type vaneCountReader struct {
	conn *vaneObservedConn
}

func (r *vaneCountReader) Read(payload []byte) (int, error) {
	n, err := r.conn.Conn.Read(payload)
	if n > 0 {
		r.conn.mu.Lock()
		r.conn.readBytes += int64(n)
		r.conn.mu.Unlock()
	}
	return n, err
}

// pendingBacklog reports bytes the relay read off the node but has not yet
// handed to the client. Only the relay's counting reader feeds readBytes; a
// direct Read/ReadBuffer on this conn does not, which is why deliveredBytes is
// its own field instead of reusing totalReadBytes. The result is clamped:
// handshake bytes can reach the client without passing through the counting
// reader, so the raw difference may go negative.
func (c *vaneObservedConn) pendingBacklog() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readBytes <= c.deliveredBytes {
		return 0
	}
	return c.readBytes - c.deliveredBytes
}

// LAST-READ: the zero value means "nothing has arrived yet", which the flow
// watchdog reports as such instead of pretending the flow is fresh.
func (c *vaneObservedConn) lastReadTime() time.Time {
	if c == nil {
		return time.Time{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastReadAt
}

func (c *vaneObservedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return &vaneCountReader{conn: c}, []N.CountFunc{func(read int64) {
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
	observation.LossRate, observation.LossSupported = c.tcpStats.lossRate()
	if observation.LossSupported {
		observation.SegsOut, observation.RetransSegs = c.tcpStats.lossCounters()
	}
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
			// Stall detection, but emit no response sample.
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
			// The read preceded send confirmation: account it for loss, but do
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
	var emptyWindow bool

	c.mu.Lock()
	c.totalReadBytes += count
	c.lastReadAt = now
	if delivered {
		c.deliveredBytes += count
	}
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
		} else {
			// §E: a full window with no qualified sample arms the valve.
			emptyWindow = true
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
	if emptyWindow && c.onEmptyWindow != nil {
		c.onEmptyWindow()
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
				if vaneActionIsImmediate(observation) {
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
// windows accumulate and races get scheduled; the dry-run policy returns nil.
// Without it, shadow can only observe delivered windows; mostly-direct reads
// never reaches the policy at all — the shadow deadlock (SHADOW-OBSERVE-001).
func (c *vaneObservedConn) enableShadowObserve() {
	c.mu.Lock()
	c.shadowObserve = true
	c.mu.Unlock()
}

// setOnEmptyWindow registers the §E valve counter hook (one per connection,
// set right after construction before any read runs).
func (c *vaneObservedConn) setOnEmptyWindow(fn func()) {
	c.mu.Lock()
	c.onEmptyWindow = fn
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
	observation := vaneThroughputObservation{
		BitsPerSecond: bitsPerSecond,
		Bytes:         bytes,
		Duration:      vaneElapsed(start, end),
		TotalBytes:    c.totalReadBytes,
		Age:           vaneElapsed(c.createdAt, now),
	}
	// One fresh TCP_INFO read per window: c.tcpStats is only filled at close
	// (the kernel counters die with the socket), so it cannot serve a live
	// window. getsockopt is local and cheap; unsupported stays false.
	stats := vaneReadTCPStats(c.Conn)
	observation.LossRate, observation.LossSupported = stats.lossRate()
	observation.Latency, observation.LatencySupported = stats.rtt()
	return observation
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
	c.lifecycleMu.Unlock()
	// FANOUT-DEADLOCK: the action commits the switch and then fans out to
	// sibling flows, whose submits re-enter requestAbort on their own conns.
	// Running the action under lifecycleMu let two sibling commits cross-wait
	// forever, so the lock now only reserves the one policy-close slot — the
	// same reserve/work/finalize shape Close() already uses.
	if !action() {
		c.mu.Lock()
		alreadyClosing := c.closing
		c.mu.Unlock()
		c.lifecycleMu.Lock()
		if !alreadyClosing && c.lifecycle == vaneConnectionPolicyClosing {
			c.lifecycle = vaneConnectionOpen
		}
		c.lifecycleMu.Unlock()
		return
	}
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
		// POLICY-CLOSE-OBSERVE: the churn/gray callbacks fire here too — a
		// policy close before relay start used to vanish from churn and gray
		// accounting, while the same close after relay start was recorded by
		// RelayFinished. The once guards keep both paths single-fire.
		c.emitCloseObservation(observation)
	}
}

func (c *vaneObservedConn) closeUnderlying() error {
	c.closeOnce.Do(func() {
		// The kernel counters die with the socket — read them
		// before Close. The read runs outside the selector lock; unsupported
		// platforms simply get nil, which the observation carries as
		// "unsupported", never as zero loss.
		stats := vaneReadTCPStats(c.Conn)
		c.mu.Lock()
		c.tcpStats = stats
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
