package mesh

import (
	"net"
	"testing"

	"p2p/core/protocol"
)

func BenchmarkEncode(b *testing.B) {
	f := &Frame{
		Broadcast: true,
		Src:       net.IPv4(10, 9, 0, 1),
		Dst:       net.IPv4(10, 9, 0, 255),
		PktID:     1234,
		TTL:       MaxTTL,
		Payload:   make([]byte, 1200),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Encode(f)
	}
}

func BenchmarkDecode(b *testing.B) {
	f := &Frame{
		Broadcast: true,
		Src:       net.IPv4(10, 9, 0, 1),
		Dst:       net.IPv4(10, 9, 0, 255),
		PktID:     1234,
		TTL:       MaxTTL,
		Payload:   make([]byte, 1200),
	}
	data := Encode(f)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRouteLearning(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(protocol.NewPeerID(), net.IPv4(10, 0, 0, 1), ipnet)

	var sentTo []string
	linkA := &Link{
		PeerID: protocol.NewPeerID(),
		Vip:    net.IPv4(10, 0, 0, 2),
		Send: func([]byte) error {
			sentTo = append(sentTo, "A")
			return nil
		},
	}
	linkB := &Link{
		PeerID: protocol.NewPeerID(),
		Vip:    net.IPv4(10, 0, 0, 3),
		Send: func([]byte) error {
			sentTo = append(sentTo, "B")
			return nil
		},
	}
	n.AddLink(linkA)
	n.AddLink(linkB)

	// A frame from 10.0.0.4 arrives via A, so the node learns that route.
	f := &Frame{
		Src:     net.IPv4(10, 0, 0, 4),
		Dst:     n.Vip,
		PktID:   1,
		TTL:     MaxTTL,
		Payload: []byte("hello"),
	}
	if err := n.Handle(linkA.PeerID, Encode(f)); err != nil {
		t.Fatal(err)
	}

	// A subsequent unicast to 10.0.0.4 should use A instead of flooding.
	if err := n.SendTo(net.IPv4(10, 0, 0, 4), []byte("data")); err != nil {
		t.Fatal(err)
	}
	if len(sentTo) != 1 || sentTo[0] != "A" {
		t.Fatalf("expected route via A only, got %v", sentTo)
	}
}
