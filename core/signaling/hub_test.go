package signaling

import (
	"net"
	"testing"

	"p2p/core/protocol"
)

func TestHubMaxMembers(t *testing.T) {
	h := NewHub()
	h.SetMaxMembers(1)
	_, network, err := net.ParseCIDR("10.9.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	m1 := &member{id: protocol.NewPeerID()}
	if _, _, err := h.join("room", "tok", m1, network); err != nil {
		t.Fatalf("first join: %v", err)
	}

	m2 := &member{id: protocol.NewPeerID()}
	if _, _, err := h.join("room", "tok", m2, network); err == nil {
		t.Fatal("expected room-full error")
	}
}
