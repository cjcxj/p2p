package signaling

import (
	"testing"
	"time"

	"p2p/core/protocol"
)

func TestServerMultiSTUNAndPunchSync(t *testing.T) {
	wantSTUN := []string{"1.1.1.1:3478", "2.2.2.2:3478", "3.3.3.3:19302"}
	srv, err := NewServer("127.0.0.1:0", Options{
		STUNServers: wantSTUN,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr().String()
	c1, err := Dial(addr, "room-1", "", nil)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.Close()

	got := c1.STUNServers()
	if len(got) != len(wantSTUN) {
		t.Fatalf("c1 STUNServers = %v, want %v", got, wantSTUN)
	}
	for i := range wantSTUN {
		if got[i] != wantSTUN[i] {
			t.Fatalf("c1 STUNServers[%d] = %q, want %q", i, got[i], wantSTUN[i])
		}
	}

	c2, err := Dial(addr, "room-1", "", nil)
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.Close()

	syncCh := make(chan protocol.Message, 1)
	c2.OnMessage = func(m protocol.Message) error {
		if m.Type == protocol.MsgPunchSync {
			syncCh <- m
		}
		return nil
	}
	go c1.Run()
	go c2.Run()

	if err := c1.Send(protocol.Message{
		Type:       protocol.MsgPunchSync,
		TargetID:   c2.PeerID().String(),
		AnchorAddr: "203.0.113.10:45123",
	}); err != nil {
		t.Fatalf("send punch_sync: %v", err)
	}

	select {
	case msg := <-syncCh:
		if msg.PeerID != c1.PeerID().String() {
			t.Fatalf("PeerID = %q, want %q", msg.PeerID, c1.PeerID().String())
		}
		if msg.AnchorAddr != "203.0.113.10:45123" {
			t.Fatalf("AnchorAddr = %q, want 203.0.113.10:45123", msg.AnchorAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MsgPunchSync forwarding")
	}
}
