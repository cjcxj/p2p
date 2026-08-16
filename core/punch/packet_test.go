package punch

import (
	"testing"

	"p2p/core/protocol"
)

func BenchmarkEncode(b *testing.B) {
	pkt := &Packet{
		Type:    PktData,
		Seq:     42,
		Src:     protocol.NewPeerID(),
		Dst:     protocol.NewPeerID(),
		Payload: make([]byte, 1200),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Encode(pkt)
	}
}

func BenchmarkDecode(b *testing.B) {
	pkt := &Packet{
		Type:    PktData,
		Seq:     42,
		Src:     protocol.NewPeerID(),
		Dst:     protocol.NewPeerID(),
		Payload: make([]byte, 1200),
	}
	data := Encode(pkt)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}
