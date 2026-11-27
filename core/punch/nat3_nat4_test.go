package punch

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/stun"
)

// udpNATSimulator emulates a real in-process NAT gateway over loopback UDP:
//   - Port-Restricted Cone (NAT3): preserves one external port per internal
//     socket and drops inbound packets unless this internal socket previously
//     sent a packet to the exact (srcIP, srcPort) of the sender.
//   - Symmetric (NAT4): allocates a separate external socket/port per
//     (internalSocket, dstAddr) using one of several realistic carrier modes
//     ("step", "preserve", "pba", "random", "multi_ip").
type udpNATSimulator struct {
	mu          sync.Mutex
	mode        string // "nat3", "step", "preserve", "pba", "random", "multi_ip"
	step        int
	nextPort    int
	pbaBase     int
	pbaSpan     int
	fixedBindIP net.IP
	closed      bool

	// Per-internal-socket mappings
	// NAT3: key = internalAddr -> extMapping
	nat3Map map[string]*extMapping
	// NAT4: key = internalAddr + "->" + dstAddr -> extMapping
	nat4Map map[string]*extMapping
	// Allowed remote endpoints per extMapping (for port-restricted filtering)
	conns []*net.UDPConn
}

type extMapping struct {
	conn      *net.UDPConn
	internal  *net.UDPAddr
	extAddr   *net.UDPAddr
	mu        sync.Mutex
	allowDsts map[string]bool
}

func newUDPNAT(t *testing.T, mode string, step int) *udpNATSimulator {
	t.Helper()
	n := &udpNATSimulator{
		mode:     mode,
		step:     step,
		nextPort: 45000 + rand.Intn(5000),
		pbaBase:  50000 + rand.Intn(5000),
		pbaSpan:  512,
		nat3Map:  make(map[string]*extMapping),
		nat4Map:  make(map[string]*extMapping),
	}
	t.Cleanup(n.close)
	return n
}

func (n *udpNATSimulator) close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	conns := n.conns
	n.conns = nil
	n.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// lanClientConn implements net.PacketConn behind the NAT simulator. Outbound
// WriteTo packets pass through the NAT's outbound translation + filtering table;
// inbound packets delivered to the NAT's external socket arrive here only if
// the NAT's inbound filter permits the sender (ip, port).
type lanClientConn struct {
	nat        *udpNATSimulator
	localSock  *net.UDPConn
	localAddr  *net.UDPAddr
	rxCh       chan simPkt
	closedOnce sync.Once
	closed     chan struct{}
}

type simPkt struct {
	data []byte
	src  net.Addr
}

func (n *udpNATSimulator) newClient(t *testing.T, requestedPort int) *lanClientConn {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: requestedPort})
	if err != nil {
		uc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("listen lan client: %v", err)
		}
	}
	lc := &lanClientConn{
		nat:       n,
		localSock: uc,
		localAddr: uc.LocalAddr().(*net.UDPAddr),
		rxCh:      make(chan simPkt, 4096),
		closed:    make(chan struct{}),
	}
	n.mu.Lock()
	n.conns = append(n.conns, uc)
	n.mu.Unlock()
	return lc
}

func (c *lanClientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case pkt := <-c.rxCh:
		n := copy(p, pkt.data)
		return n, pkt.src, nil
	}
}

func (c *lanClientConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("bad addr type %T", addr)
	}
	ext, err := c.nat.routeOutbound(c, ua)
	if err != nil {
		return 0, err
	}
	ext.mu.Lock()
	ext.allowDsts[ua.String()] = true
	ext.mu.Unlock()
	return ext.conn.WriteToUDP(p, ua)
}

func (c *lanClientConn) Close() error {
	c.closedOnce.Do(func() {
		close(c.closed)
		_ = c.localSock.Close()
	})
	return nil
}

func (c *lanClientConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *lanClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *lanClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *lanClientConn) SetWriteDeadline(t time.Time) error { return nil }

func (n *udpNATSimulator) routeOutbound(lc *lanClientConn, dst *net.UDPAddr) (*extMapping, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, net.ErrClosed
	}

	if n.mode == "nat3" {
		key := lc.localAddr.String()
		if em, ok := n.nat3Map[key]; ok {
			return em, nil
		}
		em, err := n.openExternalSocket(lc, 0)
		if err != nil {
			return nil, err
		}
		n.nat3Map[key] = em
		return em, nil
	}

	// NAT4 symmetric modes allocate per (internalAddr, dstAddr)
	key := lc.localAddr.String() + "->" + dst.String()
	if em, ok := n.nat4Map[key]; ok {
		return em, nil
	}
	desiredPort := 0
	switch n.mode {
	case "step":
		desiredPort = n.nextPort
		n.nextPort += n.step
		if n.nextPort > 65000 {
			n.nextPort = 45000
		}
	case "preserve":
		desiredPort = lc.localAddr.Port + 100
		if desiredPort > 65000 {
			desiredPort = 0
		}
	case "pba":
		desiredPort = n.pbaBase + rand.Intn(n.pbaSpan)
	case "random", "multi_ip":
		// OS ephemeral port mimics random 1024..65535 allocation
		desiredPort = 0
	}
	em, err := n.openExternalSocket(lc, desiredPort)
	if err != nil {
		return nil, err
	}
	n.nat4Map[key] = em
	return em, nil
}

func (n *udpNATSimulator) openExternalSocket(lc *lanClientConn, desiredPort int) (*extMapping, error) {
	bindIP := net.IPv4(127, 0, 0, 1)
	if n.fixedBindIP != nil {
		bindIP = n.fixedBindIP
	} else if n.mode == "multi_ip" && rand.Intn(2) == 1 {
		bindIP = net.IPv4(127, 0, 0, 2)
	}
	var uc *net.UDPConn
	var err error
	for try := 0; try < 5; try++ {
		p := desiredPort
		if try > 0 {
			p = 0
		}
		uc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: p})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	em := &extMapping{
		conn:      uc,
		internal:  lc.localAddr,
		extAddr:   uc.LocalAddr().(*net.UDPAddr),
		allowDsts: make(map[string]bool),
	}
	n.conns = append(n.conns, uc)

	go func() {
		buf := make([]byte, 4096)
		for {
			nr, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Port-restricted cone & symmetric filtering:
			// DROP inbound packet unless this external mapping has sent to (src.IP, src.Port)!
			em.mu.Lock()
			allowed := em.allowDsts[src.String()]
			em.mu.Unlock()
			if !allowed {
				continue
			}
			pktCopy := append([]byte(nil), buf[:nr]...)
			select {
			case lc.rxCh <- simPkt{data: pktCopy, src: src}:
			case <-lc.closed:
				return
			}
		}
	}()
	return em, nil
}

// probeSTUN simulates sending a STUN binding request to a virtual STUN port so
// we learn what external address the NAT allocates toward that STUN destination.
func (n *udpNATSimulator) stunMap(lc *lanClientConn, stunDst *net.UDPAddr) *net.UDPAddr {
	em, err := n.routeOutbound(lc, stunDst)
	if err != nil {
		return nil
	}
	return em.extAddr
}

func TestNAT3ToNAT4PureDirectPunching(t *testing.T) {
	cases := []struct {
		name     string
		nat4Mode string
		step     int
		poolSize int
		timeout  time.Duration
		multiIP  bool
		pool26   bool
	}{
		{name: "linear_step_symmetric", nat4Mode: "step", step: 118, poolSize: 128, timeout: 6 * time.Second},
		{name: "port_preserving_symmetric", nat4Mode: "preserve", step: 0, poolSize: 64, timeout: 6 * time.Second},
		{name: "pba_block_symmetric", nat4Mode: "pba", step: 0, poolSize: 64, timeout: 6 * time.Second},
		{name: "random_birthday_cgnat", nat4Mode: "random", step: 0, poolSize: 128, timeout: 8 * time.Second},
		{name: "rotating_multi_ip_cgnat", nat4Mode: "multi_ip", step: 0, poolSize: 128, timeout: 8 * time.Second, multiIP: true},
		{name: "pool_26_weighted_256sock", nat4Mode: "random", step: 0, poolSize: 256, timeout: 6 * time.Second, pool26: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nat3 := newUDPNAT(t, "nat3", 0)
			nat4 := newUDPNAT(t, tc.nat4Mode, tc.step)

			// Fake STUN targets to learn public mappings cleanly without relying on external network
			stun1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
			stun2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3479}

			c3 := nat3.newClient(t, 0)

			pool4 := make([]net.PacketConn, tc.poolSize)
			poolPorts4 := make([]int, tc.poolSize)
			for i := 0; i < tc.poolSize; i++ {
				lc := nat4.newClient(t, 0)
				pool4[i] = lc
				poolPorts4[i] = lc.localAddr.Port
			}

			pub3 := nat3.stunMap(c3, stun1)
			pub4 := nat4.stunMap(pool4[0].(*lanClientConn), stun1)
			pub4Alt := nat4.stunMap(pool4[0].(*lanClientConn), stun2)

			id3 := protocol.NewPeerID()
			id4 := protocol.NewPeerID()

			info3 := NATInfo{
				Type:       stun.NatPortRestrictedCone,
				PublicAddr: pub3,
			}
			info4 := NATInfo{
				Type:       stun.NatSymmetric,
				PublicAddr: pub4,
				PortDelta:  pub4Alt.Port - pub4.Port,
				PoolSize:   tc.poolSize,
			}
			switch tc.nat4Mode {
			case "step":
				info4.PortStep = tc.step
			case "preserve":
				info4.PortPreserve = true
				info4.PortPreserveOffset = 100
				info4.PoolPorts = poolPorts4
			case "pba":
				info4.PortBlockMin = nat4.pbaBase
				info4.PortBlockMax = nat4.pbaBase + nat4.pbaSpan - 1
			case "multi_ip":
				info4.PublicIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2)}
			}
			if tc.pool26 {
				_, cidr, _ := net.ParseCIDR("127.0.0.0/26")
				info4.PoolCIDR = cidr
			}

			cfg := Config{
				PortPrediction:    true,
				EnableLAN:         false, // force public NAT traversal only
				ProbeIntervalMs:   30,
				PredictionSockets: tc.poolSize,
				SymmetricSpray:    512,
				PunchPPS:          6000,
			}

			p3 := New(c3, id3, info3, cfg)
			p4 := New(pool4[0], id4, info4, cfg)
			p4.Conns = pool4

			conn3 := make(chan string, 1)
			conn4 := make(chan string, 1)
			p3.OnState = func(id protocol.PeerID, tr, ep string) {
				if tr == StatePunched {
					select {
					case conn3 <- ep:
					default:
					}
				}
			}
			p4.OnState = func(id protocol.PeerID, tr, ep string) {
				if tr == StatePunched {
					select {
					case conn4 <- ep:
					default:
					}
				}
			}

			dataCh := make(chan string, 1)
			p4.OnData = func(src protocol.PeerID, pkt *Packet) error {
				select {
				case dataCh <- string(pkt.Payload):
				default:
				}
				return nil
			}

			p3.Start()
			p4.Start()
			t.Cleanup(func() {
				_ = c3.Close()
				for _, lc := range pool4 {
					_ = lc.Close()
				}
				p3.Stop()
				p4.Stop()
			})

			p3.AddPeer(id4, info4)
			p4.AddPeer(id3, info3)

			select {
			case ep := <-conn3:
				t.Logf("%s: NAT3 punched NAT4 directly at %s", tc.name, ep)
			case <-time.After(tc.timeout):
				t.Fatalf("%s: NAT3 did not punch NAT4 within %s", tc.name, tc.timeout)
			}

			select {
			case ep := <-conn4:
				t.Logf("%s: NAT4 punched NAT3 directly at %s", tc.name, ep)
			case <-time.After(tc.timeout):
				t.Fatalf("%s: NAT4 did not punch NAT3 within %s", tc.name, tc.timeout)
			}

			// Verify bidirectional data flows directly through the punched NAT mappings
			if err := p3.Send(id4, []byte("pure-p2p-nat3-to-nat4")); err != nil {
				t.Fatalf("p3.Send: %v", err)
			}
			select {
			case got := <-dataCh:
				if got != "pure-p2p-nat3-to-nat4" {
					t.Fatalf("payload = %q, want pure-p2p-nat3-to-nat4", got)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("data packet did not cross punched NAT3<->NAT4 link")
			}
		})
	}
}

// TestProbeLoopEscalatesMisdetectedCone proves that even if STUN flakily
// misclassified a real symmetric NAT4 peer as NatPortRestrictedCone (so initial
// probes emit zero spray/plant), EscalateAfterMs triggers automatic escalation
// to full plant+spray and punches directly.
func TestProbeLoopEscalatesMisdetectedCone(t *testing.T) {
	nat3 := newUDPNAT(t, "nat3", 0)
	nat4 := newUDPNAT(t, "random", 0)

	c3 := nat3.newClient(t, 0)
	pool4 := make([]*lanClientConn, 128)
	for i := range pool4 {
		pool4[i] = nat4.newClient(t, 0)
	}

	stun1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	pub3 := nat3.stunMap(c3, stun1)
	pub4 := nat4.stunMap(pool4[0], stun1)

	id3 := protocol.NewPeerID()
	id4 := protocol.NewPeerID()

	// Misclassified as cone on both ends!
	my3 := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pub3, PrivateAddr: c3.localAddr}
	my4 := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pub4, PrivateAddr: pool4[0].localAddr}
	info4AsCone := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pub4, PrivateAddr: pool4[0].localAddr}
	info3AsCone := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pub3, PrivateAddr: c3.localAddr}

	p3 := New(c3, id3, my3, Config{
		PortPrediction:    true,
		EnableLAN:         false,
		PredictionSockets: 128,
		SymmetricSpray:    256,
		ProbeIntervalMs:   30,
		PunchPPS:          5000,
		EscalateAfterMs:   150,
	})
	conns4 := make([]net.PacketConn, len(pool4))
	for i, lc := range pool4 {
		conns4[i] = lc
	}
	p4 := New(pool4[0], id4, my4, Config{
		PortPrediction:    true,
		EnableLAN:         false,
		PredictionSockets: len(conns4),
		SymmetricSpray:    256,
		ProbeIntervalMs:   30,
		PunchPPS:          5000,
		EscalateAfterMs:   150,
	})
	p4.Conns = conns4

	conn3 := make(chan string, 1)
	conn4 := make(chan string, 1)
	p3.OnState = func(id protocol.PeerID, tr, ep string) {
		if tr == StatePunched {
			select {
			case conn3 <- ep:
			default:
			}
		}
	}
	p4.OnState = func(id protocol.PeerID, tr, ep string) {
		if tr == StatePunched {
			select {
			case conn4 <- ep:
			default:
			}
		}
	}

	p3.Start()
	p4.Start()
	t.Cleanup(func() {
		_ = c3.Close()
		for _, lc := range pool4 {
			_ = lc.Close()
		}
		p3.Stop()
		p4.Stop()
	})

	p3.AddPeer(id4, info4AsCone)
	p4.AddPeer(id3, info3AsCone)

	select {
	case ep := <-conn3:
		t.Logf("escalated NAT3 punched misdetected NAT4 at %s", ep)
	case <-time.After(8 * time.Second):
		t.Fatal("NAT3 did not recover misdetected NAT4 after escalation")
	}
	select {
	case ep := <-conn4:
		t.Logf("escalated NAT4 punched NAT3 at %s", ep)
	case <-time.After(8 * time.Second):
		t.Fatal("NAT4 did not punch NAT3 after escalation")
	}
}

// TestNat34UnsampledColdPoolIPRescue models the hard carrier CGNAT case (such
// as China Unicom's .102 pool): STUN only observed .10/.14/.26 inside a /27
// pool, while NAT4's actual egress toward NAT3 binds strictly on un-sampled cold
// IP .18. With the 128-port cold-IP floor, NAT3 rescues the cold IP cleanly at
// production 3000 PPS without waiting 20+ rounds.
func TestNat34UnsampledColdPoolIPRescue(t *testing.T) {
	nat3 := newUDPNAT(t, "nat3", 0)
	nat4 := newUDPNAT(t, "random", 0)
	nat4.fixedBindIP = net.IPv4(127, 0, 0, 18) // never sampled by STUN!

	c3 := nat3.newClient(t, 0)
	pool4 := make([]net.PacketConn, 256)
	for i := range pool4 {
		pool4[i] = nat4.newClient(t, 0)
	}

	stun1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	pub3 := nat3.stunMap(c3, stun1)

	id3 := protocol.NewPeerID()
	id4 := protocol.NewPeerID()

	_, pool27, _ := net.ParseCIDR("127.0.0.0/27")
	info3 := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pub3}
	// Advertise sampled STUN IPs .10, .14, .26 + /27 pool; .18 is strictly cold!
	info4 := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 40000},
		PublicIPs:  []net.IP{net.IPv4(127, 0, 0, 14), net.IPv4(127, 0, 0, 26)},
		PoolCIDR:   pool27,
		PoolSize:   len(pool4),
	}

	cfg := Config{
		PortPrediction:    true,
		EnableLAN:         false,
		PredictionSockets: len(pool4),
		SymmetricSpray:    256,
		SprayIPMax:        64,
		ProbeIntervalMs:   60,
		PunchPPS:          3000,
	}

	p3 := New(c3, id3, info3, cfg)
	p4 := New(pool4[0], id4, info4, cfg)
	p4.Conns = pool4

	conn3 := make(chan string, 1)
	dataCh := make(chan string, 1)
	p3.OnState = func(id protocol.PeerID, tr, ep string) {
		if tr == StatePunched {
			select {
			case conn3 <- ep:
			default:
			}
		}
	}
	p4.OnData = func(src protocol.PeerID, pkt *Packet) error {
		select {
		case dataCh <- string(pkt.Payload):
		default:
		}
		return nil
	}

	p3.Start()
	p4.Start()
	t.Cleanup(func() {
		_ = c3.Close()
		for _, lc := range pool4 {
			_ = lc.Close()
		}
		p3.Stop()
		p4.Stop()
	})

	p3.AddPeer(id4, info4)
	p4.AddPeer(id3, info3)

	select {
	case ep := <-conn3:
		t.Logf("unsampled cold IP rescue succeeded at %s", ep)
	case <-time.After(15 * time.Second):
		t.Fatal("failed to rescue un-sampled cold pool IP 127.0.0.18 within 15s")
	}

	if err := p3.Send(id4, []byte("cold-pool-rescue-ok")); err != nil {
		t.Fatalf("p3.Send: %v", err)
	}
	select {
	case got := <-dataCh:
		if got != "cold-pool-rescue-ok" {
			t.Fatalf("got %q, want cold-pool-rescue-ok", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data did not traverse rescued un-sampled pool IP link")
	}
}

// delayedDropConn wraps a PacketConn and drops outbound writes until allowAfter.
type delayedDropConn struct {
	net.PacketConn
	mu         sync.Mutex
	allowAfter time.Time
}

func (d *delayedDropConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	d.mu.Lock()
	allow := d.allowAfter
	d.mu.Unlock()
	if time.Now().Before(allow) {
		return len(p), nil
	}
	return d.PacketConn.WriteTo(p, addr)
}

// TestRouteTierNonDowngrade verifies ICE-style strict upgrade-only transitions
// (Public < UPnP < IPv6 < LAN), protection against unconfirmed one-way
// PktProbe hijacks, and immunity against delayed lower-tier PktAck downgrades.
func TestRouteTierNonDowngrade(t *testing.T) {
	idMe := protocol.NewPeerID()

	my := NATInfo{
		Type:        stun.NatPortRestrictedCone,
		PublicAddr:  addr("203.0.113.10", 40000),
		PrivateAddr: addr("192.168.1.10", 5000),
	}
	peerInf := NATInfo{
		Type:        stun.NatSymmetric,
		PublicAddr:  addr("203.0.113.20", 41000),
		PrivateAddr: addr("192.168.1.20", 5001),
		UPnPAddr:    addr("203.0.113.20", 35001),
		IPv6Addr:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6001},
	}

	p := New(nil, idMe, my, Config{EnableLAN: true})
	ps := &peer{info: peerInf, stop: make(chan struct{})}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// 1. Connect via Public on PktAck.
	first, upg, conf := ps.note(p, peerInf.PublicAddr, 0, true, 8*time.Millisecond)
	if !first || upg || !conf || ps.tier != tierPublic || ps.transport != StatePunched || !ps.confirmed {
		t.Fatalf("step public: first=%v upg=%v conf=%v tier=%s tr=%s confirmed=%v", first, upg, conf, ps.tier, ps.transport, ps.confirmed)
	}

	// 2. One-way PktProbe on LAN must NOT switch confirmed Public path yet.
	if f, u, c := ps.note(p, peerInf.PrivateAddr, 0, false, 0); f || u || c || ps.tier != tierPublic {
		t.Fatalf("unconfirmed probe wrongly switched tier: f=%v u=%v c=%v tier=%s", f, u, c, ps.tier)
	}

	// 3. Bidirectional PktAck on UPnP -> upgrades Public -> UPnP.
	first, upg, conf = ps.note(p, peerInf.UPnPAddr, 0, true, 5*time.Millisecond)
	if first || !upg || !conf || ps.tier != tierUPnP {
		t.Fatalf("step upnp: first=%v upg=%v conf=%v tier=%s", first, upg, conf, ps.tier)
	}

	// 4. Bidirectional PktAck on IPv6 (sockIdx=-1) -> upgrades UPnP -> IPv6.
	first, upg, conf = ps.note(p, peerInf.IPv6Addr, -1, true, 4*time.Millisecond)
	if first || !upg || !conf || ps.tier != tierIPv6 || ps.sockIdx != -1 {
		t.Fatalf("step ipv6: first=%v upg=%v conf=%v tier=%s sock=%d", first, upg, conf, ps.tier, ps.sockIdx)
	}

	// 5. Bidirectional PktAck on LAN -> upgrades IPv6 -> LAN.
	first, upg, conf = ps.note(p, peerInf.PrivateAddr, 0, true, 1*time.Millisecond)
	if first || !upg || !conf || ps.tier != tierLAN || ps.sockIdx != 0 {
		t.Fatalf("step lan: first=%v upg=%v conf=%v tier=%s sock=%d", first, upg, conf, ps.tier, ps.sockIdx)
	}

	// 6. Delayed IPv6 / UPnP / Public PktAck+PktData must NEVER downgrade LAN.
	for name, tc := range map[string]struct {
		ua   *net.UDPAddr
		sock int
	}{
		"ipv6":   {ua: peerInf.IPv6Addr, sock: -1},
		"upnp":   {ua: peerInf.UPnPAddr, sock: 0},
		"public": {ua: peerInf.PublicAddr, sock: 0},
	} {
		if f, u, c := ps.note(p, tc.ua, tc.sock, true, 0); f || u || c || ps.tier != tierLAN {
			t.Fatalf("%s wrongly downgraded LAN: f=%v u=%v c=%v tier=%s", name, f, u, c, ps.tier)
		}
	}
}

// TestICEDelayedHigherTierUpgradeLive proves end-to-end that when Public
// connects first while the higher-tier path (IPv6Conn) is initially blocked:
//  1. Traffic connects immediately on Public without waiting.
//  2. probeLoop continues low-overhead higher-tier probing and upgrades both
//     sides seamlessly once the higher tier unblocks.
//  3. Data flows over the upgraded link, and delayed lower-tier packets never downgrade it.
func TestICEDelayedHigherTierUpgradeLive(t *testing.T) {
	natPubA := newUDPNAT(t, "nat3", 0)
	natPubB := newUDPNAT(t, "nat3", 0)
	pubClientA := natPubA.newClient(t, 0)
	pubClientB := natPubB.newClient(t, 0)

	highRawA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	highRawB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	unblockAt := time.Now().Add(250 * time.Millisecond)
	highA := &delayedDropConn{PacketConn: highRawA, allowAfter: unblockAt}
	highB := &delayedDropConn{PacketConn: highRawB, allowAfter: unblockAt}

	stunSrv := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}
	pubAddrA := natPubA.stunMap(pubClientA, stunSrv)
	pubAddrB := natPubB.stunMap(pubClientB, stunSrv)
	hiAddrA := highRawA.LocalAddr().(*net.UDPAddr)
	hiAddrB := highRawB.LocalAddr().(*net.UDPAddr)

	idA := protocol.NewPeerID()
	idB := protocol.NewPeerID()

	infoA := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pubAddrA, IPv6Addr: hiAddrA}
	infoB := NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: pubAddrB, IPv6Addr: hiAddrB}

	cfg := Config{
		EnableLAN:       false,
		ProbeIntervalMs: 30,
		PunchPPS:        1000,
	}

	pA := New(pubClientA, idA, infoA, cfg)
	pB := New(pubClientB, idB, infoB, cfg)
	pA.IPv6Conn = highA
	pB.IPv6Conn = highB

	confirmedSocksA := make(chan int, 8)
	pA.OnDirectConfirmed = func(id protocol.PeerID, sockIdx int) {
		confirmedSocksA <- sockIdx
	}

	dataB := make(chan string, 4)
	pB.OnData = func(src protocol.PeerID, pkt *Packet) error {
		dataB <- string(pkt.Payload)
		return nil
	}

	pA.Start()
	pB.Start()
	t.Cleanup(func() {
		_ = pubClientA.Close()
		_ = pubClientB.Close()
		_ = highRawA.Close()
		_ = highRawB.Close()
		pA.Stop()
		pB.Stop()
	})

	pA.AddPeer(idB, infoB)
	pB.AddPeer(idA, infoA)

	// Phase 1: Expect fast connection on Public (sockIdx 0) BEFORE higher-tier unblocks.
	select {
	case s0 := <-confirmedSocksA:
		if s0 != 0 {
			t.Fatalf("expected initial confirmation on socket 0 (public), got %d", s0)
		}
	case <-time.After(220 * time.Millisecond):
		t.Fatal("initial Public path did not confirm quickly")
	}

	// Phase 2: Wait for higher-tier (-1) upgrade once delayedDropConn opens at 250ms.
	deadline := time.After(3 * time.Second)
	upgradedToHigh := false
	for !upgradedToHigh {
		select {
		case s1 := <-confirmedSocksA:
			if s1 == -1 {
				upgradedToHigh = true
			}
		case <-deadline:
			tierA, epA, _ := pA.PeerRoute(idB)
			t.Fatalf("did not upgrade to higher-tier socket -1; current tier=%s ep=%s", tierA, epA)
		}
	}

	waitUp := time.Now().Add(1 * time.Second)
	for time.Now().Before(waitUp) {
		tB, _, _ := pB.PeerRoute(idA)
		if tB == "ipv6" {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	tierA, epA, rttA := pA.PeerRoute(idB)
	tierB, epB, _ := pB.PeerRoute(idA)
	if tierA != "ipv6" || tierB != "ipv6" {
		t.Fatalf("expected both sides upgraded to ipv6, got A=%s(%s) B=%s(%s)", tierA, epA, tierB, epB)
	}
	if rttA <= 0 {
		t.Fatalf("expected non-zero measured RTT after PktAck upgrade, got %s", rttA)
	}

	// Phase 3: Inject a late lower-tier PktAck on Public (sockIdx=0) and verify NO downgrade.
	pA.handle(&Packet{Type: PktAck, Seq: 1, Src: idB, Dst: idA}, pubAddrB, 0)
	if afterTier, _, _ := pA.PeerRoute(idB); afterTier != "ipv6" {
		t.Fatalf("delayed public ack downgraded route to %s", afterTier)
	}

	// Phase 4: Verify data delivery over the upgraded link.
	if err := pA.Send(idB, []byte("upgraded-route-data")); err != nil {
		t.Fatalf("pA.Send after upgrade: %v", err)
	}
	select {
	case got := <-dataB:
		if got != "upgraded-route-data" {
			t.Fatalf("got %q, want upgraded-route-data", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data did not cross upgraded link")
	}
}

func TestMeasureRTTClampsSubTickAndSkipsKeepalive(t *testing.T) {
	ps := &peer{}
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if got := ps.measureRTTLocked(0); got != 0 {
		t.Fatalf("keepalive seq 0 should report 0, got %s", got)
	}

	// Simulate uint16 wraparound skipping 0 and sub-tick measurement (same/future monotonic tick).
	ps.seq = 65535
	seq := ps.nextProbeSeqLocked()
	if seq != 1 {
		t.Fatalf("wrapped probe seq = %d, want 1", seq)
	}
	ps.probeSent[seq&511].sent = time.Now().Add(time.Millisecond)
	if got := ps.measureRTTLocked(seq); got != time.Microsecond {
		t.Fatalf("sub-tick probe RTT = %s, want >= 1µs (%s)", got, time.Microsecond)
	}
}

func TestConfirmedPeerIgnoresRoamingProbeLastSeen(t *testing.T) {
	cA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cA.Close()

	idA := protocol.NewPeerID()
	idB := protocol.NewPeerID()
	oldAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.10").To4(), Port: 41000}
	roamAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.20").To4(), Port: 42000}

	pA := New(cA, idA, NATInfo{Type: stun.NatPortRestrictedCone}, Config{EnableLAN: true})
	pA.AddPeer(idB, NATInfo{Type: stun.NatSymmetric, PublicAddr: oldAddr})
	ps := pA.peer(idB)
	if ps == nil {
		t.Fatal("missing peer")
	}

	// Simulate an already-confirmed link on oldAddr with an aged lastSeen.
	aged := time.Now().Add(-30 * time.Second)
	ps.mu.Lock()
	ps.endpoint = oldAddr
	ps.sockIdx = 0
	ps.tier = tierPublic
	ps.transport = StatePunched
	ps.connected = true
	ps.confirmed = true
	ps.lastSeen = aged
	ps.mu.Unlock()

	// A stray/roaming one-way PktProbe from roamAddr is rejected by note() and
	// must NOT refresh lastSeen.
	pA.handle(&Packet{Type: PktProbe, Seq: 7, Src: idB, Dst: idA}, roamAddr, 0)
	ps.mu.Lock()
	gotSeen := ps.lastSeen
	gotEp := ps.endpoint.String()
	ps.mu.Unlock()
	if !gotSeen.Equal(aged) {
		t.Fatalf("rejected roaming probe refreshed lastSeen: got %v, want %v", gotSeen, aged)
	}
	if gotEp != oldAddr.String() {
		t.Fatalf("rejected roaming probe overwrote endpoint to %s", gotEp)
	}

	// Bidirectional PktAck from roamAddr at same tier updates endpoint and refreshes lastSeen.
	pA.handle(&Packet{Type: PktAck, Seq: 8, Src: idB, Dst: idA}, roamAddr, 0)
	ps.mu.Lock()
	gotSeen = ps.lastSeen
	gotEp = ps.endpoint.String()
	ps.mu.Unlock()
	if !gotSeen.After(aged) {
		t.Fatalf("PktAck did not refresh lastSeen")
	}
	if gotEp != roamAddr.String() {
		t.Fatalf("PktAck did not switch endpoint to %s (got %s)", roamAddr, gotEp)
	}
}

