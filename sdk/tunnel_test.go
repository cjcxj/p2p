package p2p

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/punch"
	"p2p/core/stun"
	"p2p/wgengine"
)

// punchedPair builds two sessions whose UDP sockets reach each other over
// loopback, with the tunnel already running -- the state a real room is in
// once signaling has exchanged candidates.
func punchedPair(t *testing.T) (a, b *Session, tunA, tunB *wgengine.FakeTUN) {
	t.Helper()
	a = fakeSession(t, net.ParseIP("10.9.0.1"))
	b = fakeSession(t, net.ParseIP("10.9.0.2"))

	tunA, tunB = wgengine.NewFakeTUN(1420), wgengine.NewFakeTUN(1420)
	if err := a.startTunnel(tunA, "p2p-a"); err != nil {
		t.Fatalf("tunnel a: %v", err)
	}
	if err := b.startTunnel(tunB, "p2p-b"); err != nil {
		t.Fatalf("tunnel b: %v", err)
	}

	// The candidate each peer would publish over signaling, delivered to the
	// other -- exactly the frame onSignaling receives.
	send := func(from, to *Session) {
		t.Helper()
		m := protocol.Message{
			Type:      protocol.MsgCandidate,
			PeerID:    from.id.String(),
			Candidate: from.buildCandidate(),
		}
		if err := to.onSignaling(m); err != nil {
			t.Fatalf("candidate to %s: %v", to.vip, err)
		}
	}
	send(a, b)
	send(b, a)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ca, _ := a.ph.Connected(b.id)
		cb, _ := b.ph.Connected(a.id)
		if ca && cb {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sessions did not punch each other")
	return
}

func fakeSession(t *testing.T, vip net.IP) *Session {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	key, err := newDataKey()
	if err != nil {
		t.Fatalf("session key: %v", err)
	}
	ua := conn.LocalAddr().(*net.UDPAddr)
	// Pretend STUN said "open NAT" and this socket is directly reachable, which
	// is what buildCandidate turns into a public candidate address.
	s := &Session{
		cfg:    Config{ProbeIntervalMs: 50, PunchTimeoutMs: 2000},
		l:      nullListener{},
		conn:   conn,
		id:     protocol.NewPeerID(),
		vip:    vip,
		ipnet:  &net.IPNet{IP: net.IPv4(10, 9, 0, 0), Mask: net.CIDRMask(24, 32)},
		x25519: key,
		room:   "test",
		peers:  make(map[string]*remote),
		det: &stun.Detection{
			NATType:    stun.NatOpen,
			MappedAddr: ua,
			LocalAddr:  ua,
		},
	}
	ph := punch.New(conn, s.id, punch.NATInfo{
		Type:        stun.NatOpen,
		PublicAddr:  ua,
		PrivateAddr: ua,
	}, punch.Config{
		EnableLAN:       true,
		PortPrediction:  false,
		ProbeIntervalMs: 50,
		PunchTimeoutMs:  2000,
	})
	ph.OnState = func(id protocol.PeerID, transport, endpoint string) {
		s.onPeerConnected(id, transport, endpoint)
	}
	ph.OnData = func(protocol.PeerID, *punch.Packet) error { return nil }
	s.ph = ph
	ph.Start()
	// The punch read loop only unblocks once the socket is closed, so both
	// happen in this one cleanup, in this order.
	t.Cleanup(func() {
		_ = conn.Close()
		ph.Stop()
	})
	return s
}

// TestSDKTunnelCarriesPunchedPeer covers the wiring between punching and the
// tunnel: the peer entry is built from the key in the signaling candidate and
// the endpoint punching produced, and a packet put on one interface arrives on
// the other side's interface decrypted.
func TestSDKTunnelCarriesPunchedPeer(t *testing.T) {
	a, b, tunA, tunB := punchedPair(t)

	// Both sides must agree on who initiates, and only one of them can.
	a.mu.Lock()
	electA := a.id.Less(b.id)
	a.mu.Unlock()
	b.mu.Lock()
	electB := b.id.Less(a.id)
	b.mu.Unlock()
	if electA == electB {
		t.Fatal("both sides elected themselves initiator")
	}

	want := echoRequest(a.vip, b.vip, 64)
	if !tunA.Inject(want) {
		t.Fatal("inject failed")
	}
	select {
	case got := <-tunB.Outbound():
		if len(got) != len(want) {
			t.Fatalf("decrypted packet length %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("packet differs at byte %d: got %02x want %02x", i, got[i], want[i])
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no packet crossed the session tunnel")
	}
}

// TestSDKCloseTUNReattachesSamePeer is the mobile shape: the VPN interface is
// turned off and on again while the room session -- and the punching behind it
// -- stays up. The second interface has to be handed the peers the first one
// already had, which only works if closing the tunnel forgets which endpoint
// each peer was configured for.
//
// Both sides re-attach: WireGuard remembers handshakes per key pair, and a
// responder that came back up with a fresh device would otherwise wait for the
// far side's stale session to time out before traffic flowed again.
func TestSDKCloseTUNReattachesSamePeer(t *testing.T) {
	a, b, _, _ := punchedPair(t)

	a.CloseTUN()
	b.CloseTUN()
	a.mu.Lock()
	afterClose := a.tunnel
	closed := a.closed
	r := a.peers[b.id.String()]
	configured := ""
	if r != nil {
		configured = r.wgEndpoint
	}
	a.mu.Unlock()
	if afterClose != nil {
		t.Fatal("CloseTUN left a tunnel running")
	}
	if closed {
		t.Fatal("CloseTUN closed the session")
	}
	if r == nil {
		t.Fatal("CloseTUN dropped the peer table")
	}
	if configured != "" {
		t.Fatalf("peer still marked configured at %s", configured)
	}

	tunA, tunB := wgengine.NewFakeTUN(1420), wgengine.NewFakeTUN(1420)
	if err := a.startTunnel(tunA, "p2p-a2"); err != nil {
		t.Fatalf("re-attach a: %v", err)
	}
	if err := b.startTunnel(tunB, "p2p-b2"); err != nil {
		t.Fatalf("re-attach b: %v", err)
	}
	defer func() {
		a.CloseTUN()
		b.CloseTUN()
	}()

	want := echoRequest(a.vip, b.vip, 64)
	// A freshly attached interface has no session yet, and WireGuard drops what
	// arrives before the handshake finishes. A kernel would retransmit, so the
	// test does too.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if !tunA.Inject(want) {
			t.Fatal("inject failed")
		}
		select {
		case got := <-tunB.Outbound():
			if len(got) != len(want) {
				t.Fatalf("decrypted packet length %d, want %d", len(got), len(want))
			}
			return
		case <-time.After(200 * time.Millisecond):
			if time.Now().After(deadline) {
				dumpTunnels(t, "after timeout", a, b)
				t.Fatal("no packet crossed the re-attached tunnel")
			}
		}
	}
}

// TestSDKOpenTUNRejectsLegacyMesh keeps the two data planes from being
// requested at once: the desktop interface is created by the tunnel, and the
// legacy bridge expects the caller to own it.
func TestSDKOpenTUNRejectsLegacyMesh(t *testing.T) {
	s, err := NewSession(&Config{LegacyMesh: true}, nullListener{})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer s.Disconnect()
	if err := s.OpenTUN(1280); err == nil {
		t.Fatal("OpenTUN accepted while the legacy mesh bridge is configured")
	}
}

func csum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// echoRequest builds an IPv4 ICMP echo request padded to total bytes -- the
// smallest thing a kernel hands a tunnel interface.
func echoRequest(src, dst net.IP, total int) []byte {
	if total < 20+8 {
		total = 20 + 8
	}
	icmpLen := total - 20
	icmp := make([]byte, icmpLen)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	for i := 8; i < icmpLen; i++ {
		icmp[i] = byte(i)
	}
	binary.BigEndian.PutUint16(icmp[2:4], csum(icmp))

	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], csum(pkt[:20]))
	copy(pkt[20:], icmp)
	return pkt
}

// dumpTunnels prints both WireGuard configs; used while debugging re-attach.
func dumpTunnels(t *testing.T, tag string, a, b *Session) {
	t.Helper()
	a.mu.Lock()
	ta := a.tunnel
	a.mu.Unlock()
	b.mu.Lock()
	tb := b.tunnel
	b.mu.Unlock()
	t.Logf("dump %s A:\n%s", tag, ta.Dump())
	t.Logf("dump %s B:\n%s", tag, tb.Dump())
}
