package punch

import "net"

// readBatchSize is the number of datagrams read per batch on Linux.
const readBatchSize = 8

// batchPacket is one datagram returned by readBatch.
type batchPacket struct {
	src  net.Addr
	data []byte
}
