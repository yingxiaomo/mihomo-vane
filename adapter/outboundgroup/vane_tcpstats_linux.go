//go:build linux

package outboundgroup

import (
	"net"

	"golang.org/x/sys/unix"
)

// vaneReadTCPStats reads the kernel's cumulative TCP counters for conn's
// socket via TCP_INFO. Only connections whose wrapper chain can be unwrapped
// to the raw TCP socket are supported (TLS wraps fine, QUIC/UDP never resolve).
// nil means "unsupported", never "no loss" — callers must not record a sample.
func vaneReadTCPStats(conn net.Conn) *vaneTCPStats {
	tcpConn := vaneUnwrapTCPConn(conn)
	if tcpConn == nil {
		return nil
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return nil
	}
	var stats *vaneTCPStats
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if infoErr != nil || info == nil {
			controlErr = infoErr
			return
		}
		stats = &vaneTCPStats{
			segsOut:      uint64(info.Segs_out),
			retransSegs:  uint64(info.Total_retrans),
			bytesSent:    info.Bytes_sent,
			bytesRetrans: info.Bytes_retrans,
			rttMicros:    info.Rtt,
		}
	}); err != nil {
		return nil
	}
	if controlErr != nil || stats == nil {
		return nil
	}
	return stats
}
