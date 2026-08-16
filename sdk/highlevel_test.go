package p2p

import "testing"

func TestHighLevel(t *testing.T) {
	h, err := NewHighLevel(Defaults(), nil)
	if err != nil {
		t.Fatalf("NewHighLevel: %v", err)
	}
	defer h.Disconnect()

	if len(h.Peers()) != 0 {
		t.Fatalf("expected no peers, got %d", len(h.Peers()))
	}
	if h.LocalIP() != "" {
		t.Fatalf("expected empty local IP before connect, got %q", h.LocalIP())
	}
	if c := h.Connect("00000000000000000000000000000000"); c == nil {
		t.Fatal("Connect returned nil connection")
	}
	if h.Session() == nil {
		t.Fatal("Session() returned nil")
	}
}
