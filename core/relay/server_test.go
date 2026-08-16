package relay

import (
	"net"
	"testing"

	"p2p/core/protocol"
	"p2p/core/punch"
)

func TestRelayMaxRoomMembers(t *testing.T) {
	s := NewServer()
	s.MaxRoomMembers = 1
	if _, err := s.Allocate("room", "tok", "127.0.0.1"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer s.Close()

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	src := conn.LocalAddr().(*net.UDPAddr)

	register := func(id protocol.PeerID) {
		pkt := &punch.Packet{Type: punch.PktRegister, Src: id, Payload: []byte("room\x00tok")}
		s.Handle(src, punch.Encode(pkt))
	}

	first := protocol.NewPeerID()
	register(first)

	s.mu.Lock()
	rs := s.rooms["room"]
	if rs == nil {
		s.mu.Unlock()
		t.Fatal("room not allocated")
	}
	if len(rs.members) != 1 {
		s.mu.Unlock()
		t.Fatalf("first member not registered: members=%d", len(rs.members))
	}
	s.mu.Unlock()

	second := protocol.NewPeerID()
	register(second)

	s.mu.Lock()
	if len(rs.members) != 1 {
		s.mu.Unlock()
		t.Fatalf("second member should be rejected, members=%d", len(rs.members))
	}
	s.mu.Unlock()
}

func TestRelayPerPeerToken(t *testing.T) {
	s := NewServer()
	if _, err := s.Allocate("room", "room-token", "127.0.0.1"); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer s.Close()

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	src := conn.LocalAddr().(*net.UDPAddr)

	first := protocol.NewPeerID()
	second := protocol.NewPeerID()
	s.Grant("room", first.String(), "peer1-token")

	register := func(id protocol.PeerID, token string) {
		pkt := &punch.Packet{Type: punch.PktRegister, Src: id, Payload: []byte("room\x00" + token)}
		s.Handle(src, punch.Encode(pkt))
	}

	// A peer with its own per-peer token registers successfully.
	register(first, "peer1-token")
	s.mu.Lock()
	rs := s.rooms["room"]
	if rs == nil {
		s.mu.Unlock()
		t.Fatal("room not allocated")
	}
	if len(rs.members) != 1 {
		s.mu.Unlock()
		t.Fatalf("per-peer token not accepted, members=%d", len(rs.members))
	}
	s.mu.Unlock()

	// Another peer cannot use the first peer's token.
	register(second, "peer1-token")
	s.mu.Lock()
	if len(rs.members) != 1 {
		s.mu.Unlock()
		t.Fatalf("peer used another peer's relay token, members=%d", len(rs.members))
	}
	s.mu.Unlock()

	// Backward compatibility: the shared room token is still accepted.
	register(second, "room-token")
	s.mu.Lock()
	if len(rs.members) != 2 {
		s.mu.Unlock()
		t.Fatalf("room-token fallback failed, members=%d", len(rs.members))
	}
	s.mu.Unlock()
}
