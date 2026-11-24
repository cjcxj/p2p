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
