//go:build !linux

package outboundgroup

import "net"

// vaneReadTCPStats has no implementation outside Linux yet: TCP_CONNECTION_INFO
// (darwin) and SIO_TCP_INFO (windows) are separate projects. nil means
// "unsupported" for every connection — callers must treat it as "no sample",
// never as "no loss".
func vaneReadTCPStats(conn net.Conn) *vaneTCPStats {
	return nil
}
