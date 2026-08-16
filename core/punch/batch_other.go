//go:build !linux

package punch

import "net"

// readBatch falls back to one datagram per call on non-Linux platforms.
func readBatch(conn net.PacketConn, bufs [][]byte) ([]batchPacket, error) {
	return readBatchSingle(conn, bufs[0])
}
