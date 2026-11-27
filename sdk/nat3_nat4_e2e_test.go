package p2p

import (
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/signaling"
	"p2p/core/stun"
	"p2p/wgengine"
)

type e2eListener struct {
	mu        sync.Mutex
	connected chan string
	errors    []string
	once      sync.Once
}

func newE2EListener() *e2eListener {
	return &e2eListener{
		connected: make(chan string, 2),
	}
}

func (l *e2eListener) OnEvent(event int, peerID string, data []byte) {
	switch event {
	case EventPeerConnected:
		l.once.Do(func() {
			l.connected <- string(data)
		})
	case EventError:
		l.mu.Lock()
		l.errors = append(l.errors, string(data))
		l.mu.Unlock()
	}
}

func startLocalSTUN(t *testing.T) *stun.Server {
	t.Helper()
	for p := 38000; p < 39000; p += 2 {
		srv, err := stun.NewServer("127.0.0.1", p, "")
		if err == nil {
			t.Cleanup(srv.Close)
			return srv
		}
	}
	t.Fatal("failed to start local STUN server")
	return nil
}

// TestSingleSignalingMultiSTUNPureDirectWireGuard verifies the full SDK path:
// single signaling server advertising multiple STUN servers -> concurrent NAT
// detection -> pure direct punching -> WireGuard tunnel packet delivery.
func TestSingleSignalingMultiSTUNPureDirectWireGuard(t *testing.T) {
	stun1 := startLocalSTUN(t)
	stun2 := startLocalSTUN(t)
	s1Addr := stun1.Addrs()[0].String()
	s2Addr := stun2.Addrs()[0].String()

	// Single signaling server pushes multi-STUN list via MsgWelcome.
	sigSrv, err := signaling.NewServer("127.0.0.1:0", signaling.Options{
		STUNServers: []string{s2Addr},
	})
	if err != nil {
		t.Fatalf("signaling NewServer: %v", err)
	}
	defer sigSrv.Close()

	makeCfg := func() *Config {
		c := Defaults()
		c.ServerAddr = sigSrv.Addr().String()
		c.STUNAddr = s1Addr
		c.PredictionSockets = 8
		c.SymmetricSpray = 64
		c.PunchPPS = 3000
		c.EnableIPv6 = false
		c.EnableUPnP = false
		c.TimeoutSec = 10
		return c
	}

	la := newE2EListener()
	lb := newE2EListener()
	sa, err := NewSession(makeCfg(), la)
	if err != nil {
		t.Fatalf("NewSession A: %v", err)
	}
	defer sa.Disconnect()

	cfgB := makeCfg()
	// Ensure B doesn't collide trying to bind StepProbePort already bound by A
	cfgB.PredictionSockets = 1
	sb, err := NewSession(cfgB, lb)
	if err != nil {
		t.Fatalf("NewSession B: %v", err)
	}
	defer sb.Disconnect()

	if err := sa.Connect("nat3-nat4-e2e"); err != nil {
		t.Fatalf("Connect A: %v", err)
	}
	if err := sb.Connect("nat3-nat4-e2e"); err != nil {
		t.Fatalf("Connect B: %v", err)
	}

	var trA, trB string
	select {
	case trA = <-la.connected:
	case <-time.After(10 * time.Second):
		t.Fatal("session A did not connect directly")
	}
	select {
	case trB = <-lb.connected:
	case <-time.After(10 * time.Second):
		t.Fatal("session B did not connect directly")
	}
	if trA != TransportPunched || trB != TransportPunched {
		t.Fatalf("expected pure direct transport %q, got A=%q B=%q", TransportPunched, trA, trB)
	}

	// Verify server-pushed multi-STUN list was merged into session A and B.
	sa.mu.Lock()
	stunsA := append([]string(nil), sa.stunList...)
	sa.mu.Unlock()
	found := false
	for _, st := range stunsA {
		if st == s2Addr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("session A did not inherit server-pushed STUN %s (got %v)", s2Addr, stunsA)
	}

	// Verify WireGuard data-plane works end-to-end on the punched link.
	tunA, tunB := wgengine.NewFakeTUN(1280), wgengine.NewFakeTUN(1280)
	if err := sa.startTunnel(tunA, "wg-e2e-a"); err != nil {
		t.Fatalf("startTunnel A: %v", err)
	}
	if err := sb.startTunnel(tunB, "wg-e2e-b"); err != nil {
		t.Fatalf("startTunnel B: %v", err)
	}

	ipA := net.ParseIP(sa.LocalIP())
	ipB := net.ParseIP(sb.LocalIP())
	if ipA == nil || ipB == nil {
		t.Fatalf("missing virtual IPs: A=%v B=%v", ipA, ipB)
	}

	want := echoRequest(ipA, ipB, 64)
	deadline := time.Now().Add(8 * time.Second)
	for {
		if !tunA.Inject(want) {
			t.Fatal("inject failed")
		}
		select {
		case got := <-tunB.Outbound():
			if len(got) == len(want) {
				return
			}
			case <-time.After(200 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("WireGuard packet did not traverse pure-direct session")
			}
		}
	}
}

func TestProductionPublishWireDecodeSpray(t *testing.T) {
	det := &stun.Detection{
		NATType:    stun.NatSymmetric,
		MappedAddr: &net.UDPAddr{IP: net.ParseIP("111.55.212.114"), Port: 7857},
		ObservedIPs: []net.IP{
			net.ParseIP("111.55.212.114"),
			net.ParseIP("111.55.212.98"),
			net.ParseIP("111.55.212.110"),
			net.ParseIP("111.55.212.106"),
		},
		PortStep: 46,
	}
	s := &Session{det: det}
	c := s.buildCandidate()

	b, err := json.Marshal(protocol.Message{Type: protocol.MsgCandidate, Candidate: c})
	if err != nil {
		t.Fatalf("wire marshal: %v", err)
	}
	var m protocol.Message
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("wire unmarshal: %v", err)
	}
	info, err := candidateToNAT(m.Candidate)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.PoolCIDR == nil {
		t.Fatalf("buildCandidate did not advertise egress pool: PublicAddr=%q", m.Candidate.PublicAddr)
	}
	for _, ip := range info.CandidateIPs() {
		if ip.String() == "111.55.212.102" {
			t.Fatal("sampled set unexpectedly contains un-observed .102")
		}
	}
	reached := false
	for _, ip := range info.SprayIPs(0, 0) {
		if ip.String() == "111.55.212.102" {
			reached = true
			break
		}
	}
	if !reached {
		t.Fatalf("production spray set missed un-sampled .102 (pool %s)", info.PoolCIDR)
	}
}

