//go:build !linux

package punch

import "net"

// readBatchSingle is the portable fallback used by readBatch.
func readBatchSingle(conn net.PacketConn, buf []byte) ([]batchPacket, error) {
	n, src, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return []batchPacket{{src: src, data: buf[:n]}}, nil
}

// readBatch falls back to one datagram per call on non-Linux platforms.
func readBatch(conn net.PacketConn, bufs [][]byte) ([]batchPacket, error) {
	return readBatchSingle(conn, bufs[0])
}
