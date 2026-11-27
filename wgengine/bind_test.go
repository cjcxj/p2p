package wgengine

import (
	"net"
	"testing"
)

// The tunnel must be able to send through a caller-supplied router instead of
// its fixed socket, so the WireGuard data plane can follow the punch engine's
// winning socket per peer.
func TestBindSendUsesSender(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	var got []byte
	var addr *net.UDPAddr
	b.SetSender(func(buf []byte, dst *net.UDPAddr) error {
		got = append([]byte(nil), buf...)
		addr = dst
		return nil
	})

	ep, err := b.ParseEndpoint("203.0.113.7:44000")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	if err := b.Send([][]byte{{9, 8, 7}}, ep); err != nil {
		t.Fatalf("send: %v", err)
	}
	if addr == nil || addr.String() != "203.0.113.7:44000" {
		t.Fatalf("router not used, dst=%v", addr)
	}
	if len(got) != 3 || got[0] != 9 {
		t.Fatalf("router payload wrong: %v", got)
	}
}

// Without a router the bind still writes through its own socket.
func TestBindSendFallsBackToConn(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	b.SetSender(nil) // no router: Send must use pc
	self := pc.LocalAddr().(*net.UDPAddr)
	ep, err := b.ParseEndpoint(self.String())
	if err != nil {
		t.Fatalf("parse self: %v", err)
	}
	if err := b.Send([][]byte{{1, 2, 3, 4}}, ep); err != nil {
		t.Fatalf("send through conn: %v", err)
	}
}

func TestBindForgetInitiationOnResponse(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41234}
	initPkt := make([]byte, 148)
	initPkt[0] = 1
	b.Ingest(initPkt, from)
	// Drain the live receive queued by Ingest.
	select {
	case in := <-b.rx:
		b.pool.Put(&in.buf)
	default:
		t.Fatal("expected initial packet queued")
	}

	// Emitting a Handshake Response (type 2) to the peer consumes the cached
	// initiation so a later RemovePeer+AddPeer does not replay a stale one.
	ep, err := b.ParseEndpoint(from.String())
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	resp := make([]byte, 92)
	resp[0] = 2
	b.SetSender(func([]byte, *net.UDPAddr) error { return nil })
	if err := b.Send([][]byte{resp}, ep); err != nil {
		t.Fatalf("send response: %v", err)
	}
	b.ReplayInitiation(from.String())
	select {
	case <-b.rx:
		t.Fatal("answered initiation was replayed")
	default:
	}

	// ForgetInitiation also drops un-answered cached initiations on peer removal.
	b.Ingest(initPkt, from)
	in := <-b.rx
	b.pool.Put(&in.buf)
	b.ForgetInitiation(from.String())
	b.ReplayInitiation(from.String())
	select {
	case <-b.rx:
		t.Fatal("forgotten initiation was replayed")
	default:
	}
}

func TestBindCacheInitEvictsOldest(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	initPkt := make([]byte, 148)
	initPkt[0] = 1
	for i := 0; i < 40; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000 + i}
		b.Ingest(initPkt, addr)
		in := <-b.rx
		b.pool.Put(&in.buf)
	}

	b.mu.Lock()
	count := len(b.recentInit)
	b.mu.Unlock()
	if count != 32 {
		t.Fatalf("recentInit len = %d, want 32 (only excess oldest evicted)", count)
	}
}

