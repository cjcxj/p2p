package punch

import (
	"encoding/binary"
	"errors"
	"sync"

	"p2p/core/protocol"
)

// encodePool reuses packet buffers on the hot send paths.
var encodePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 2048)
	},
}

// Magic marks every UDP packet of this protocol.
const Magic = 0x504E4348 // "PNCH"

// Packet types.
const (
	PktProbe    uint8 = 1
	PktAck      uint8 = 2
	PktData     uint8 = 3
	PktRegister uint8 = 4
	PktRegAck   uint8 = 5
	PktProbe2   uint8 = 6
)

// packetHeaderLen is the fixed part of every packet (magic,type,seq,src,dst,len).
const packetHeaderLen = 4 + 1 + 2 + 16 + 16 + 2

// Packet is a protocol packet.
type Packet struct {
	Type    uint8
	Seq     uint16
	Src     protocol.PeerID
	Dst     protocol.PeerID
	Payload []byte
}

// Encode serialises a packet.
func Encode(p *Packet) []byte {
	buf := make([]byte, packetHeaderLen+len(p.Payload))
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = p.Type
	binary.BigEndian.PutUint16(buf[5:7], p.Seq)
	copy(buf[7:23], p.Src[:])
	copy(buf[23:39], p.Dst[:])
	binary.BigEndian.PutUint16(buf[39:41], uint16(len(p.Payload)))
	copy(buf[41:], p.Payload)
	return buf
}

// encodePooled serialises a packet into a pooled buffer. The caller must call
// putEncode on the returned slice after the underlying WriteTo has returned.
func encodePooled(p *Packet) []byte {
	buf := encodePool.Get().([]byte)[:0]
	buf = append(buf, make([]byte, packetHeaderLen+len(p.Payload))...)
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = p.Type
	binary.BigEndian.PutUint16(buf[5:7], p.Seq)
	copy(buf[7:23], p.Src[:])
	copy(buf[23:39], p.Dst[:])
	binary.BigEndian.PutUint16(buf[39:41], uint16(len(p.Payload)))
	copy(buf[41:], p.Payload)
	return buf
}

// putEncode returns a buffer obtained from encodePooled to the pool.
func putEncode(buf []byte) {
	encodePool.Put(buf[:0])
}

// Decode parses a packet. It returns an error for short or foreign packets.
func Decode(b []byte) (*Packet, error) {
	if len(b) < packetHeaderLen {
		return nil, errors.New("punch: short packet")
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return nil, errors.New("punch: bad magic")
	}
	p := &Packet{
		Type: b[4],
		Seq:  binary.BigEndian.Uint16(b[5:7]),
	}
	copy(p.Src[:], b[7:23])
	copy(p.Dst[:], b[23:39])
	plen := int(binary.BigEndian.Uint16(b[39:41]))
	if len(b) < packetHeaderLen+plen {
		return nil, errors.New("punch: truncated payload")
	}
	p.Payload = append([]byte(nil), b[41:41+plen]...)
	return p, nil
}
