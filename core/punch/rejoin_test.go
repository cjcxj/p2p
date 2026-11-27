package punch

import (
	"net"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/stun"
)

// openSocket returns a real UDP socket plus the NATInfo that announces it as
// directly reachable -- the open-NAT shape these loopback tests punch through.
func openSocket(t *testing.T) (*net.UDPConn, NATInfo) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ua := c.LocalAddr().(*net.UDPAddr)
	return c, NATInfo{Type: stun.NatOpen, PublicAddr: ua, PrivateAddr: ua}
}

func waitConnected(p *Punch, id protocol.PeerID, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok, _ := p.Connected(id); ok {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func endpointOf(p *Punch, id protocol.PeerID) string {
	ps := p.peer(id)
	if ps == nil {
		return ""
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.endpoint == nil {
		return ""
	}
	return ps.endpoint.String()
}

// TestNat34RejoinRepunchesAfterPeerRestart is the same restart under a filtering
// NAT, which is what makes the stale flag fatal rather than merely untidy: the
// surviving side only lets in destinations it has itself sent to, so a peer that
// re-dials (new egress address, same id) stays unreachable until this side
// re-plans. This is the user's "disconnect, reconnect, never reconnects" on the
// wire.
func TestNat34RejoinRepunchesAfterPeerRestart(t *testing.T) {
	in := &internet{owner: map[string]*nat{}}
	hard := Config{PredictionSockets: 8, PeerPortOffset: 2, SymmetricSpray: 512,
		ProbeIntervalMs: 1, PunchTimeoutMs: 9000, PunchPPS: 1000000}
	soft := Config{PredictionSockets: 1, SymmetricSpray: 512,
		ProbeIntervalMs: 1, PunchTimeoutMs: 9000, PunchPPS: 1000000}
	id4, id3 := protocol.NewPeerID(), protocol.NewPeerID()
	adv3 := &net.UDPAddr{IP: net.ParseIP("127.9.0.3").To4(), Port: 40000}

	// Session one: the symmetric NAT34 pair punches normally. The candidate is
	// built the way the passing NAT34 tests build it -- the advertised address is
	// the server-direction IP and the peer-direction egress rides along in
	// PublicIPs, which is what the spray aims at.
	first := newNat(in, true, rotatingPool, 8)
	second := newNat(in, false, []string{"127.9.0.3"}, 1)
	egress := first[0].n.external(0, adv3)
	advIP, candIPs := otherPoolIP(rotatingPool, egress.IP)
	adv := &net.UDPAddr{IP: advIP, Port: 6000}
	ph4 := New(first[0], id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv}, hard)
	ph4.Conns = asPC(first)
	ph3 := New(second[0], id3, NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: adv3}, soft)
	ph3.Conns = asPC(second)
	ph4.Start()
	ph3.Start()
	defer func() {
		closeAll(first)
		closeAll(second)
		ph4.Stop()
		ph3.Stop()
	}()
	ph4.AddPeer(id3, NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: adv3})
	ph3.AddPeer(id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv, PublicIPs: candIPs})
	if !waitBoth(ph4, id3, ph3, id4, 10*time.Second) {
		t.Fatal("the first session never punched; the harness is not set up as the other NAT34 tests do")
	}
	dead := endpointOf(ph3, id4)

	// The symmetric peer's session ends and it re-dials: its sockets are gone and
	// the carrier hands it a different egress pool. It keeps its peer id, exactly
	// like an app that reconnects.
	closeAll(first)
	rebornPool := []string{"127.0.5.212", "127.0.5.216", "127.0.5.220"}
	reborn := newNat(in, true, rebornPool, 8)
	egress2 := reborn[0].n.external(0, adv3)
	advIP2, candIPs2 := otherPoolIP(rebornPool, egress2.IP)
	adv2 := &net.UDPAddr{IP: advIP2, Port: 6000}
	ph4b := New(reborn[0], id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv2}, hard)
	ph4b.Conns = asPC(reborn)
	ph4b.Start()
	defer func() {
		closeAll(reborn)
		ph4b.Stop()
	}()
	ph4b.AddPeer(id3, NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: adv3})
	// Signaling carries the restarted peer's new candidate to the survivor. This
	// AddPeer is the whole difference between recovering and staying dead.
	ph3.AddPeer(id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv2, PublicIPs: candIPs2})
	if !waitBoth(ph4b, id3, ph3, id4, 12*time.Second) {
		t.Fatalf("the link never came back: ph3 still reports %s, ph4b connected=%v",
			endpointOf(ph3, id4), func() bool { ok, _ := ph4b.Connected(id3); return ok }())
	}
	if got := endpointOf(ph3, id4); got == dead || got == "" {
		t.Fatalf("ph3 is pinned to the dead session's endpoint (%s)", got)
	}
}

func closeAll(conns []*natConn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// otherPoolIP returns the pool address a NAT reports toward the observation point
// (one that is not the address it happens to use toward our peer) and the
// candidate IP list a multi-point STUN would have produced for it.
func otherPoolIP(pool []string, egress net.IP) (net.IP, []net.IP) {
	egress = egress.To4()
	for _, s := range pool {
		ip := net.ParseIP(s).To4()
		if ip.Equal(egress) {
			continue
		}
		return ip, []net.IP{ip, egress}
	}
	return egress, []net.IP{egress}
}

// waitBoth reports when both engines have a punched link to the other. Each side
// has to be asked about the OTHER peer's id.
func waitBoth(a *Punch, aTarget protocol.PeerID, b *Punch, bTarget protocol.PeerID, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		oa, ta := a.Connected(aTarget)
		ob, tb := b.Connected(bTarget)
		if oa && ob && ta == StatePunched && tb == StatePunched {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

// TestRejoinClearsStaleLink covers the reconnect deadlock: the peer restarts --
// same id, new socket -- and re-announces itself. The engine must not carry the
// old session's "connected" verdict over, because a probe loop that starts with it
// goes straight to keepalive aimed at an address the peer has already left behind.
// A rejoined peer cannot be reached until this side opens its half of the mapping,
// so the newcomer then probes a closed door and the link stays dark.
func TestRejoinClearsStaleLink(t *testing.T) {
	sockA, infoA := openSocket(t)
	sockB, infoB := openSocket(t)
	idA, idB := protocol.NewPeerID(), protocol.NewPeerID()
	quick := Config{EnableLAN: true, ProbeIntervalMs: 20, PunchTimeoutMs: 4000}
	a := New(sockA, idA, infoA, quick)
	b := New(sockB, idB, infoB, quick)
	// Stop waits for the read loop, which only unblocks once its socket is gone.
	t.Cleanup(func() { _ = sockA.Close(); a.Stop() })
	t.Cleanup(func() { _ = sockB.Close(); b.Stop() })
	a.AddPeer(idB, infoB)
	b.AddPeer(idA, infoA)
	a.Start()
	b.Start()
	if !waitConnected(a, idB, 5*time.Second) {
		t.Fatal("the first session never punched")
	}
	dead := endpointOf(a, idB)
	if dead == "" {
		t.Fatal("connected without recording an endpoint")
	}

	// B goes away and comes back on a different socket under the same id.
	_ = sockB.Close()
	sockB2, infoB2 := openSocket(t)
	b2 := New(sockB2, idB, infoB2, quick)
	t.Cleanup(func() { _ = sockB2.Close(); b2.Stop() })
	b2.AddPeer(idA, infoA)
	b2.Start()
	a.AddPeer(idB, infoB2)
	if ok, transport := a.Connected(idB); ok {
		t.Fatalf("AddPeer kept the restarted peer marked connected (%s at %s)", transport, dead)
	}
	if !waitConnected(a, idB, 5*time.Second) {
		t.Fatal("A never reached the restarted peer")
	}
	if got := endpointOf(a, idB); got == dead {
		t.Fatalf("A is pinned to the dead session's endpoint %s", got)
	}
}
