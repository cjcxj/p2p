package punch

import (
	"io"
	"net"
	"testing"
	"time"

	"p2p/core/protocol"
)

// recConn records the destination and count of each WriteTo so a test can prove
// which pool socket SendWireGuard selected.
type recConn struct {
	idx    int
	writes int
	dst    net.Addr
}

func (c *recConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *recConn) WriteTo(_ []byte, a net.Addr) (int, error) {
	c.writes++
	c.dst = a
	return 0, nil
}
func (c *recConn) Close() error                              { return nil }
func (c *recConn) LocalAddr() net.Addr                        { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30000 + c.idx} }
func (c *recConn) SetDeadline(time.Time) error               { return nil }
func (c *recConn) SetReadDeadline(time.Time) error           { return nil }
func (c *recConn) SetWriteDeadline(time.Time) error          { return nil }

// The WireGuard data plane must leave through the socket that actually punched
// the peer, not the primary socket, so it rides the same live NAT mapping.
func TestSendWireGuardUsesWinningSocket(t *testing.T) {
	c0 := &recConn{idx: 0}
	c1 := &recConn{idx: 1}
	c2 := &recConn{idx: 2}
	p := &Punch{
		Conns: []net.PacketConn{c0, c1, c2},
		peers: make(map[protocol.PeerID]*peer),
	}
	ep := &net.UDPAddr{IP: net.ParseIP("203.0.113.9").To4(), Port: 51000}
	id := protocol.NewPeerID()
	p.peers[id] = &peer{endpoint: ep, sockIdx: 2, connected: true, transport: StatePunched}

	if err := p.SendWireGuard([]byte{0x04, 1, 2, 3}, ep); err != nil {
		t.Fatalf("send: %v", err)
	}
	if c2.writes != 1 {
		t.Fatalf("winning socket (idx 2) got %d writes, want 1", c2.writes)
	}
	if c0.writes != 0 {
		t.Fatalf("primary socket wrongly used for a punched peer (%d writes)", c0.writes)
	}
}

// An endpoint belonging to no punched peer (relay, or roaming) falls back to the
// primary socket rather than dropping the frame.
func TestSendWireGuardFallsBackToPrimary(t *testing.T) {
	c0 := &recConn{idx: 0}
	c1 := &recConn{idx: 1}
	p := &Punch{Conns: []net.PacketConn{c0, c1}, peers: make(map[protocol.PeerID]*peer)}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.99").To4(), Port: 60000}
	if err := p.SendWireGuard([]byte{0x04}, other); err != nil {
		t.Fatalf("send: %v", err)
	}
	if c0.writes != 1 {
		t.Fatalf("unknown endpoint should use primary socket, got %d writes there", c0.writes)
	}
}
