//go:build linux

package punch

import (
	"net"

	"golang.org/x/net/ipv4"
)

// readBatch reads up to len(bufs) datagrams in one syscall on Linux.
func readBatch(conn net.PacketConn, bufs [][]byte) ([]batchPacket, error) {
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return readBatchSingle(conn, bufs[0])
	}
	pc := ipv4.NewPacketConn(uc)
	msgs := make([]ipv4.Message, len(bufs))
	for i := range msgs {
		msgs[i].Buffers = [][]byte{bufs[i]}
	}
	n, err := pc.ReadBatch(msgs, 0)
	if err != nil {
		return nil, err
	}
	out := make([]batchPacket, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, batchPacket{
			src:  msgs[i].Addr,
			data: msgs[i].Buffers[0][:msgs[i].N],
		})
	}
	return out, nil
}
