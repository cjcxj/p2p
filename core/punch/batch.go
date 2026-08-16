package punch

import "net"

// readBatchSize is the number of datagrams read per batch on Linux.
const readBatchSize = 8

// batchPacket is one datagram returned by readBatch.
type batchPacket struct {
	src  net.Addr
	data []byte
}

// readBatchSingle is the portable fallback used by readBatch on platforms
// without recvmmsg, and by the Linux implementation when the connection is
// not a *net.UDPConn.
func readBatchSingle(conn net.PacketConn, buf []byte) ([]batchPacket, error) {
	n, src, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return []batchPacket{{src: src, data: buf[:n]}}, nil
}
