package outboundgroup

import (
	"net"
	"reflect"
	"time"
	"unsafe"
)

// vaneTCPStats snapshots the kernel's cumulative TCP counters for one socket.
// Both sides are monotonic over the socket lifetime, so a single read at
// settle time yields the connection's cumulative retransmission ratio.
type vaneTCPStats struct {
	segsOut      uint64
	retransSegs  uint64
	bytesSent    uint64
	bytesRetrans uint64
	// rttMicros is TCP_INFO's smoothed RTT. Zero means the kernel has no timed
	// sample yet, not "instant".
	rttMicros uint32
}

// rtt returns the socket's smoothed RTT. ok is false when the kernel reported
// no timed sample (or the read was unsupported) — never "zero latency".
func (s *vaneTCPStats) rtt() (time.Duration, bool) {
	if s == nil || s.rttMicros == 0 {
		return 0, false
	}
	return time.Duration(s.rttMicros) * time.Microsecond, true
}

// lossCounters returns the raw denominator and numerator behind lossRate:
// segments first, bytes as the fallback, so a node-level cumulative ratio
// stays consistent with the per-socket one.
func (s *vaneTCPStats) lossCounters() (uint64, uint64) {
	if s == nil {
		return 0, 0
	}
	if s.segsOut > 0 {
		return s.segsOut, s.retransSegs
	}
	return s.bytesSent, s.bytesRetrans
}

// lossRate returns the socket's cumulative retransmission ratio. Segments are
// the primary denominator; the byte ratio is the fallback when the kernel did
// not report segment counts. ok is false when nothing was ever sent: a socket
// without evidence cannot claim a loss rate. A nil stats pointer means the
// read was unsupported, never "no loss".
func (s *vaneTCPStats) lossRate() (float64, bool) {
	if s == nil {
		return 0, false
	}
	if s.segsOut > 0 {
		return float64(s.retransSegs) / float64(s.segsOut), true
	}
	if s.bytesSent > 0 {
		return float64(s.bytesRetrans) / float64(s.bytesSent), true
	}
	return 0, false
}

// vaneTCPUnwrapDepth bounds the wrapper walk so a malicious or buggy wrapper
// chain cannot spin the reader.
const vaneTCPUnwrapDepth = 256

// vaneUnwrapTCPConn peels transport wrappers (TLS, stat and metric conns,
// multiplexers) off until the raw *net.TCPConn appears. Wrappers are followed
// through their Upstream()/NetConn() exits first, then by reflection over
// struct fields. Cycles and dead ends return nil: "unsupported", which callers
// must distinguish from a genuine zero loss rate.
func vaneUnwrapTCPConn(conn net.Conn) *net.TCPConn {
	visited := make(map[uintptr]bool)
	current := conn
	for step := 0; current != nil && step < vaneTCPUnwrapDepth; step++ {
		if tcpConn, ok := current.(*net.TCPConn); ok {
			return tcpConn
		}
		value := reflect.ValueOf(current)
		if value.Kind() != reflect.Ptr || value.IsNil() {
			return nil
		}
		key := value.Pointer()
		if visited[key] {
			return nil
		}
		visited[key] = true
		switch unwrapped := current.(type) {
		case interface{ Upstream() net.Conn }:
			current = unwrapped.Upstream()
		case interface{ Upstream() any }:
			next, ok := unwrapped.Upstream().(net.Conn)
			if !ok {
				return nil
			}
			current = next
		case interface{ NetConn() net.Conn }:
			current = unwrapped.NetConn()
		default:
			current = vaneReflectTCPUnwrap(current)
		}
	}
	return nil
}

// vaneReflectTCPUnwrap descends into a wrapper struct that hides its wrapped
// connection in a (possibly unexported) field. Ambiguity or absence stops the
// walk: guessing between two connection-shaped fields could inspect the wrong
// socket, and an unsupported read is safer than a wrong one.
func vaneReflectTCPUnwrap(current net.Conn) net.Conn {
	value := reflect.ValueOf(current)
	if value.Kind() != reflect.Ptr || value.IsNil() {
		return nil
	}
	structValue := value.Elem()
	if structValue.Kind() != reflect.Struct {
		return nil
	}
	connType := reflect.TypeOf((*net.Conn)(nil)).Elem()
	var found reflect.Value
	for index := 0; index < structValue.NumField(); index++ {
		field := structValue.Field(index)
		if !field.Type().Implements(connType) {
			continue
		}
		if found.IsValid() {
			return nil
		}
		found = field
	}
	if !found.IsValid() {
		return nil
	}
	if found.CanInterface() {
		next, _ := found.Interface().(net.Conn)
		return next
	}
	// Unexported field: the Implements check above already proved the type,
	// so read it through an unsafe alias of the same address.
	inner := reflect.NewAt(found.Type(), unsafe.Pointer(found.UnsafeAddr())).Elem()
	next, _ := inner.Interface().(net.Conn)
	return next
}
