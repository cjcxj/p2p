package p2p

import (
	"net"
	"testing"

	"p2p/core/protocol"
)

type recordingListener struct {
	events []int
	peers  []string
	data   []string
}

func (l *recordingListener) OnEvent(event int, peerID string, data []byte) {
	l.events = append(l.events, event)
	l.peers = append(l.peers, peerID)
	l.data = append(l.data, string(data))
}

func TestPathChangedEventOnDirectEndpointUpgrade(t *testing.T) {
	l := &recordingListener{}
	s := &Session{
		l:     l,
		peers: make(map[string]*remote),
	}
	id := protocol.NewPeerID()
	s.peers[id.String()] = &remote{id: id, vip: net.IPv4(10, 9, 0, 2), wgPub: "0011"}

	s.onPeerConnected(id, TransportPunched, "203.0.113.5:40000")
	s.onPeerConnected(id, TransportPunched, "192.168.1.20:5000")

	if len(l.events) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(l.events), l.events)
	}
	if l.events[0] != EventPeerConnected {
		t.Fatalf("first event = %d, want EventPeerConnected(%d)", l.events[0], EventPeerConnected)
	}
	if l.events[1] != EventPathChanged {
		t.Fatalf("second event = %d, want EventPathChanged(%d)", l.events[1], EventPathChanged)
	}
	s.mu.Lock()
	r := s.peers[id.String()]
	r.wgApplied = tunnelPeer{pub: "0011", endpoint: "203.0.113.5:40000", vip: "10.9.0.2"}
	tp, _, needTunnel := s.tunnelPeer(id.String(), r)
	s.mu.Unlock()
	if !needTunnel || tp.endpoint != "192.168.1.20:5000" {
		t.Fatalf("expected tunnelPeer update to 192.168.1.20:5000, got need=%v tp=%+v", needTunnel, tp)
	}
}
