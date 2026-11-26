package wgengine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/punch"
	"p2p/core/stun"
)

// keypair returns a WireGuard key pair in the shape the SDK already exchanges:
// a crypto/ecdh X25519 key whose public half is hex advertised in signaling and
// whose private half is handed to WireGuard unclamped. The tunnel working with
// these keys is what proves Candidate.X25519Pub needs no wire format change.
func keypair(t testing.TB) (privHex, pubHex string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return hex.EncodeToString(priv.Bytes()), hex.EncodeToString(priv.PublicKey().Bytes())
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

var (
	vipA = net.ParseIP("10.9.0.1")
	vipB = net.ParseIP("10.9.0.2")
)

// echoRequest builds an IPv4 ICMP echo request of the given total length, which
// is the kind of packet a kernel hands a tunnel interface.
func echoRequest(src, dst net.IP, total int) []byte {
	if total < 48 {
		total = 48
	}
	icmp := make([]byte, total-20)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	for i := range icmp[8:] {
		icmp[8+i] = byte(i + 1)
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

func listen(t testing.TB) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func puncher(t testing.TB, c *net.UDPConn, id protocol.PeerID) *punch.Punch {
	t.Helper()
	ua := c.LocalAddr().(*net.UDPAddr)
	return punch.New(c, id, punch.NATInfo{
		Type:        stun.NatOpen,
		PublicAddr:  ua,
		PrivateAddr: ua,
	}, punch.Config{
		EnableLAN:       true,
		PortPrediction:  false,
		ProbeIntervalMs: 50,
		PunchTimeoutMs:  2000,
	})
}

// pair is two WireGuard interfaces, each running on the UDP socket its own punch
// engine owns, with the hole already punched.
type pair struct {
	tunA, tunB *FakeTUN
	addA, addB func(initiator bool) error
	pa, pb     *punch.Punch
	idA, idB   protocol.PeerID
}

func dial(t testing.TB) *pair {
	t.Helper()
	idA, idB := protocol.NewPeerID(), protocol.NewPeerID()
	sockA, sockB := listen(t), listen(t)
	addrA := sockA.LocalAddr().(*net.UDPAddr)
	addrB := sockB.LocalAddr().(*net.UDPAddr)

	pa := puncher(t, sockA, idA)
	pb := puncher(t, sockB, idB)
	// Punch.Stop waits for its read loop, which only unblocks once the socket it
	// is parked on is closed -- so close first, in this one cleanup.
	t.Cleanup(func() {
		_ = sockA.Close()
		_ = sockB.Close()
		pa.Stop()
		pb.Stop()
	})
	pa.AddPeer(idB, punch.NATInfo{Type: stun.NatOpen, PublicAddr: addrB, PrivateAddr: addrB})
	pb.AddPeer(idA, punch.NATInfo{Type: stun.NatOpen, PublicAddr: addrA, PrivateAddr: addrA})
	pa.Start()
	pb.Start()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ca, _ := pa.Connected(idB)
		cb, _ := pb.Connected(idA)
		if ca && cb {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ok, transport := pa.Connected(idB); !ok {
		t.Fatalf("hole punching did not complete between the two sockets (transport %s)", transport)
	}

	privA, pubA := keypair(t)
	privB, pubB := keypair(t)

	tunA, tunB := NewFakeTUN(1420), NewFakeTUN(1420)
	tA := New(tunA, sockA, false)
	tB := New(tunB, sockB, false)
	t.Cleanup(func() {
		tA.Stop()
		tB.Stop()
	})

	// Route the punch read loop's WireGuard datagrams into each tunnel.
	pa.SetWireGuardSink(tA.Bind().Ingest)
	pb.SetWireGuardSink(tB.Bind().Ingest)

	if err := tA.Start(privA); err != nil {
		t.Fatalf("tunnel A up: %v", err)
	}
	if err := tB.Start(privB); err != nil {
		t.Fatalf("tunnel B up: %v", err)
	}

	return &pair{
		tunA: tunA, tunB: tunB,
		pa: pa, pb: pb,
		idA: idA, idB: idB,
		addA: func(initiator bool) error {
			return tA.AddPeer(pubB, addrB.String(), vipB.String(), initiator)
		},
		addB: func(initiator bool) error {
			return tB.AddPeer(pubA, addrA.String(), vipA.String(), initiator)
		},
	}
}

// addPeers configures both sides, electing the initiator from the two peer ids
// exactly as the SDK does. Which side finishes configuring first is not ours to
// choose, so initiatorFirst reproduces the unlucky ordering too.
func (p *pair) addPeers(t testing.TB, initiatorFirst bool) {
	t.Helper()
	initA := p.idA.Less(p.idB)
	if initA == initiatorFirst {
		if err := p.addA(initA); err != nil {
			t.Fatalf("peer on A: %v", err)
		}
		if err := p.addB(!initA); err != nil {
			t.Fatalf("peer on B: %v", err)
		}
		return
	}
	if err := p.addB(!initA); err != nil {
		t.Fatalf("peer on B: %v", err)
	}
	if err := p.addA(initA); err != nil {
		t.Fatalf("peer on A: %v", err)
	}
}

// established returns a pair whose WireGuard session is already running, which is
// the state per packet cost and steady throughput should be measured in.
func established(t testing.TB) *pair {
	t.Helper()
	p := dial(t)
	p.addPeers(t, false)
	if !p.tunA.Inject(echoRequest(vipA, vipB, 120)) {
		t.Fatal("inject failed")
	}
	select {
	case <-p.tunB.Outbound():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel never delivered its first packet")
	}
	return p
}

// TestTunnelOverPunchedSocket proves a WireGuard interface can run on the very
// UDP socket the punch engine owns: punching completes, the tunnel is brought up
// on the same socket, and an IP packet injected on one side comes out the other
// side decrypted -- while punch frames and WireGuard frames share one
// demultiplexer.
//
// Both configuration orders are covered because they behave differently: the side
// that opens the handshake can send its initiation before the far side has the
// peer configured, which WireGuard would otherwise only recover from five
// seconds later.
func TestTunnelOverPunchedSocket(t *testing.T) {
	t.Run("initiator configures first", func(t *testing.T) { testTunnelPair(t, true) })
	t.Run("responder configures first", func(t *testing.T) { testTunnelPair(t, false) })
}

func testTunnelPair(t *testing.T, initiatorFirst bool) {
	p := dial(t)
	p.addPeers(t, initiatorFirst)

	want := echoRequest(vipA, vipB, 44)
	if !p.tunA.Inject(want) {
		t.Fatal("inject failed")
	}

	// The first packet pays the Noise handshake; a following one rides the
	// established session and shows the steady-state cost of the tunnel.
	start := time.Now()
	var got []byte
	select {
	case got = <-p.tunB.Outbound():
	case <-time.After(10 * time.Second):
		t.Fatal("no decrypted packet emerged: tunnel over the punched socket did not deliver")
	}
	up := time.Since(start)
	t.Logf("first packet %v after the peers were configured", up)
	if up > 2*time.Second {
		t.Errorf("first packet took %v: handshake did not complete on the first attempts", up)
	}
	if len(got) != len(want) {
		t.Fatalf("decrypted packet length %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decrypted packet differs at byte %d: got %02x want %02x", i, got[i], want[i])
		}
	}

	injected := time.Now()
	if !p.tunA.Inject(echoRequest(vipA, vipB, 44)) {
		t.Fatal("second inject failed")
	}
	select {
	case <-p.tunB.Outbound():
		t.Logf("established-path latency: %v", time.Since(injected))
	case <-time.After(5 * time.Second):
		t.Fatal("second packet never arrived")
	}

	// The punch engine must still be able to use the same socket afterwards.
	if err := p.pa.Send(p.idB, []byte("still works")); err != nil {
		t.Fatalf("punch send after tunnel up: %v", err)
	}
}

// TestDemuxDoesNotStealPunchFrames checks the leading-byte classifier leaves
// punch and STUN frames to their own handlers.
func TestDemuxClassifier(t *testing.T) {
	if punch.IsWireGuard([]byte{'P', 'N', 'C', 'H', 1}) {
		t.Error("PNCH frame misclassified as WireGuard")
	}
	if punch.IsWireGuard([]byte{'M', 'S', 'H', 'M'}) {
		t.Error("MSHM frame misclassified as WireGuard")
	}
	// STUN Binding Request: 0x0001 length 0x0020, magic cookie 0x2112A442
	if punch.IsWireGuard([]byte{0x00, 0x01, 0x00, 0x20, 0x21, 0x12, 0xa4, 0x42}) {
		t.Error("STUN Binding Request misclassified as WireGuard")
	}
	// STUN Binding Success Response: 0x0101
	if punch.IsWireGuard([]byte{0x01, 0x01, 0x00, 0x0c}) {
		t.Error("STUN Binding Success misclassified as WireGuard")
	}
	// WireGuard handshake initiation is type 1, data is type 4.
	if !punch.IsWireGuard([]byte{1, 0, 0, 0}) {
		t.Error("WireGuard handshake initiation not detected")
	}
	if !punch.IsWireGuard([]byte{4, 0, 0, 0}) {
		t.Error("WireGuard data message not detected")
	}
}
