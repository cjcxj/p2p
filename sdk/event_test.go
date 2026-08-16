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

func TestPathChangedEvent(t *testing.T) {
	l := &recordingListener{}
	s := &Session{
		l:     l,
		peers: make(map[string]*remote),
	}
	id := protocol.NewPeerID()
	s.peers[id.String()] = &remote{id: id, vip: net.IPv4(10, 9, 0, 2)}

	s.onPeerConnected(id, TransportRelay)
	s.onPeerConnected(id, TransportPunched)

	if len(l.events) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(l.events), l.events)
	}
	if l.events[0] != EventPeerConnected {
		t.Fatalf("first event = %d, want EventPeerConnected(%d)", l.events[0], EventPeerConnected)
	}
	if l.events[1] != EventPathChanged {
		t.Fatalf("second event = %d, want EventPathChanged(%d)", l.events[1], EventPathChanged)
	}
	if l.data[1] != TransportPunched {
		t.Fatalf("path change data = %q, want %q", l.data[1], TransportPunched)
	}
}
