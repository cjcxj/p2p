package punch

import (
	"net"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/stun"
)

func lanFixture() (*Punch, *peer, protocol.PeerID, *net.UDPAddr, *net.UDPAddr) {
	lanNet := &net.IPNet{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.CIDRMask(24, 32)}
	my := NATInfo{
		Type:         stun.NatPortRestrictedCone,
		PrivateAddr:  &net.UDPAddr{IP: net.ParseIP("192.168.1.10").To4(), Port: 30000},
		PrivateCIDRs: []*net.IPNet{lanNet},
	}
	peerPriv := &net.UDPAddr{IP: net.ParseIP("192.168.1.31").To4(), Port: 30000}
	peerPub := &net.UDPAddr{IP: net.ParseIP("1.2.3.4").To4(), Port: 40000}
	info := NATInfo{
		Type:         stun.NatPortRestrictedCone,
		PublicAddr:   peerPub,
		PrivateAddr:  peerPriv,
		PrivateCIDRs: []*net.IPNet{lanNet},
	}
	id := protocol.NewPeerID()
	c0 := &recConn{idx: 0}
	p := &Punch{
		Conn:   c0,
		Conns:  []net.PacketConn{c0},
		MyID:   protocol.NewPeerID(),
		My:     my,
		Config: Config{EnableLAN: true},
		peers:  map[protocol.PeerID]*peer{},
	}
	ps := &peer{info: info, lastSeen: time.Now()}
	p.peers[id] = ps
	return p, ps, id, peerPriv, peerPub
}

// A straggler on the public mapping must not steal the data path away from a LAN
// session, and the other direction -- discovering a better path after connecting
// on a worse one -- must take it.
func TestRouteTierNeverDowngrades(t *testing.T) {
	p, ps, _, peerPriv, peerPub := lanFixture()

	ps.note(p, peerPub, 0)
	if ps.tier != tierPublic {
		t.Fatalf("first path tier = %s, want public", ps.tier)
	}
	if _, upgraded := ps.note(p, peerPriv, 0); !upgraded {
		t.Fatal("moving from public to LAN was not reported as an upgrade")
	}
	if ps.tier != tierLAN || ps.endpoint.String() != peerPriv.String() {
		t.Fatalf("after LAN packet: tier %s endpoint %s", ps.tier, ps.endpoint)
	}

	// Now the late public packet arrives.
	ps.note(p, peerPub, 0)
	if ps.endpoint.String() != peerPriv.String() || ps.tier != tierLAN {
		t.Fatalf("a public straggler downgraded the route to %s (%s)", ps.endpoint, ps.tier)
	}
}

// This is the rule that keeps a stale endpoint from looking alive for ever: only
// traffic that needs a working path in both directions may refresh the idle
// clock. Our keepalives are PktAck, so a healthy peer still renews it.
func TestOneWayProbesDoNotKeepAStaleRouteAlive(t *testing.T) {
	p, ps, id, _, peerPub := lanFixture()
	ps.note(p, peerPub, 0)

	stale := time.Now().Add(-2 * peerIdleTimeout)

	ps.mu.Lock()
	ps.lastSeen = stale
	ps.mu.Unlock()
	p.handle(&Packet{Type: PktProbe, Seq: 1, Src: id, Dst: p.MyID}, peerPub, 0)
	ps.mu.Lock()
	afterProbe := ps.lastSeen
	ps.mu.Unlock()
	if !afterProbe.Equal(stale) {
		t.Fatalf("a one-way probe refreshed liveness (%v moved to %v)", stale, afterProbe)
	}

	ps.mu.Lock()
	ps.lastSeen = stale
	ps.mu.Unlock()
	p.handle(&Packet{Type: PktAck, Seq: 1, Src: id, Dst: p.MyID}, peerPub, 0)
	ps.mu.Lock()
	afterAck := ps.lastSeen
	ps.mu.Unlock()
	if afterAck.Equal(stale) {
		t.Fatal("a bidirectional PktAck did not refresh liveness")
	}
}

// A peer that restarted is re-added through AddPeer, which must also forget the
// tier: keeping the old high tier would reject the new session's first, lower-tier
// packet and leave the peer unreachable behind a stale verdict.
func TestAddPeerForgetsTheOldTier(t *testing.T) {
	p, ps, id, peerPriv, _ := lanFixture()
	ps.note(p, peerPriv, 0)
	if ps.tier != tierLAN {
		t.Fatalf("fixture did not reach the LAN tier (got %s)", ps.tier)
	}

	p.AddPeer(id, NATInfo{
		Type:       stun.NatPortRestrictedCone,
		PublicAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.9").To4(), Port: 41000},
	})
	defer p.RemovePeer(id)

	ps2 := p.peer(id)
	ps2.mu.Lock()
	tier, connected := ps2.tier, ps2.connected
	ps2.mu.Unlock()
	if connected {
		t.Fatal("AddPeer left the restarted peer marked connected")
	}
	if tier != tierNone {
		t.Fatalf("AddPeer kept tier %s from the dead session, want none", tier)
	}
}
