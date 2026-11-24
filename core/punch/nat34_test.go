package punch

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"p2p/core/protocol"
	"p2p/core/stun"
)

// Deterministic in-memory NAT model driving the REAL Punch engines through
// NAT3 (port-restricted cone) <-> NAT4 (destination-rotating symmetric), proving
// the plant + multi-IP-spray strategy actually traverses them. The negative
// control (peer-direction egress NOT in the candidate set -> no punch) is the
// honesty guard: it shows the spray must really reach the rotating address and
// the strict filters are not being bypassed.

var delivered int64

type frame struct {
	src  *net.UDPAddr
	dst  *net.UDPAddr
	data []byte
}

type internet struct {
	mu    sync.Mutex
	owner map[string]*nat
}

func (in *internet) register(a *net.UDPAddr, n *nat) {
	in.mu.Lock()
	in.owner[a.String()] = n
	in.mu.Unlock()
}

func (in *internet) route(f frame) {
	in.mu.Lock()
	n := in.owner[f.dst.String()]
	in.mu.Unlock()
	if n != nil {
		n.receive(f)
	}
}

type nat struct {
	in     *internet
	sym    bool
	poolIP []string
	conns  []*natConn
	mu     sync.Mutex
}

func hashIP(ip net.IP) uint32 {
	ip = ip.To4()
	var h uint32
	for _, b := range ip {
		h = h*131 + uint32(b)
	}
	return h
}

// egressIP is the public IP this NAT presents toward dst. Cone: fixed pool[0];
// symmetric: rotates by destination.
func (n *nat) egressIP(dst net.IP) string {
	if !n.sym {
		return n.poolIP[0]
	}
	return n.poolIP[int(hashIP(dst))%len(n.poolIP)]
}

// external is the (ip,port) internal socket idx uses toward dst. Cone keeps a
// stable port per socket (that is what a cone peer is reachable at regardless of
// destination); symmetric varies the port, and here we SPREAD it across the full
// unprivileged range keyed by (idx,dst) -- a realistic fully-random CGNAT, so the
// spray is proven to converge on scattered egress ports, not just clustered ones.
func (n *nat) external(idx int, dst *net.UDPAddr) *net.UDPAddr {
	if !n.sym {
		return &net.UDPAddr{IP: net.ParseIP(n.egressIP(dst.IP)).To4(), Port: 40000 + idx}
	}
	// Deterministic but well-spread across [1024, 65535].
	h := hashIP(dst.IP)*2654435761 + uint32(idx)*40503
	return &net.UDPAddr{
		IP:   net.ParseIP(n.egressIP(dst.IP)).To4(),
		Port: 1024 + int(h%64000),
	}
}

func (n *nat) receive(f frame) {
	n.mu.Lock()
	target := -1
	for i, c := range n.conns {
		if c.ownsExternal(f.dst) && c.allowedFrom(f.src) {
			target = i
			break
		}
	}
	n.mu.Unlock()
	if target < 0 {
		return
	}
	atomic.AddInt64(&delivered, 1)
	select {
	case n.conns[target].rx <- f:
	default:
	}
}

type natConn struct {
	n      *nat
	idx    int
	rx     chan frame
	once   sync.Once
	closed chan struct{}
	mu     sync.Mutex
	exts   map[string]bool
	sentTo map[string]bool
}

func (c *natConn) ownsExternal(a *net.UDPAddr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exts[a.String()]
}

func (c *natConn) allowedFrom(src *net.UDPAddr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sentTo[src.String()]
}

func (c *natConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	d := dst.(*net.UDPAddr)
	ext := c.n.external(c.idx, d)
	c.mu.Lock()
	c.exts[ext.String()] = true
	c.sentTo[d.String()] = true
	c.mu.Unlock()
	c.n.in.register(ext, c.n)
	c.n.in.route(frame{src: ext, dst: d, data: append([]byte(nil), b...)})
	return len(b), nil
}

func (c *natConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case f := <-c.rx:
		copy(b, f.data)
		return len(f.data), f.src, nil
	}
}

func (c *natConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, byte(c.idx+1)), Port: 30000 + c.idx}
}
func (c *natConn) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *natConn) SetDeadline(time.Time) error        { return nil }
func (c *natConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *natConn) SetWriteDeadline(t time.Time) error { return nil }

func newNat(in *internet, sym bool, poolIP []string, pool int) []*natConn {
	n := &nat{in: in, sym: sym, poolIP: poolIP}
	conns := make([]*natConn, pool)
	for i := 0; i < pool; i++ {
		conns[i] = &natConn{n: n, idx: i, rx: make(chan frame, 8192), closed: make(chan struct{}),
			exts: map[string]bool{}, sentTo: map[string]bool{}}
	}
	n.conns = conns
	return conns
}

func asPC(conns []*natConn) []net.PacketConn {
	out := make([]net.PacketConn, len(conns))
	for i, c := range conns {
		out[i] = c
	}
	return out
}

// runNat34 punches a NAT4<->NAT3 pair. poolIP is the NAT4's egress IP pool:
// size 1 models an IP-stable symmetric NAT (only the port rotates per
// destination, reachable with a single candidate and no multi-STUN breadth);
// a larger pool models a destination-rotating CGNAT (reachable only when the
// published candidate set includes the peer-direction IP). includeEgress picks
// whether that IP is in the candidate set.
func runNat34(t *testing.T, poolIP []string, includeEgress bool) bool {
	t.Helper()
	atomic.StoreInt64(&delivered, 0)
	in := &internet{owner: map[string]*nat{}}

	p4 := newNat(in, true, poolIP, 8)                 // NAT4 symmetric, pool for plant
	p3 := newNat(in, false, []string{"127.9.0.3"}, 1) // NAT3 cone, single socket

	// Real externals each side is reachable at (computed the same way the NAT
	// allocates them, so advertised == listening). Cone is destination-agnostic.
	adv3 := p3[0].n.external(0, &net.UDPAddr{IP: net.ParseIP(poolIP[0]).To4(), Port: 1})
	// NAT4's egress toward the NAT3 peer (the rotating address under test):
	egress4to3 := p4[0].n.external(0, adv3)
	egressIPStr := egress4to3.IP.String()
	// adv4 = the relay-reported (server-direction) IP. Pick a pool IP != the
	// egress so the negative case is meaningful; for a size-1 pool the two are
	// necessarily the same (an IP-stable symmetric NAT).
	adv4IP, wrongIP := egressIPStr, egressIPStr
	for _, s := range poolIP {
		if s == egressIPStr {
			continue
		}
		if adv4IP == egressIPStr {
			adv4IP = s
		} else if wrongIP == egressIPStr {
			wrongIP = s
		}
	}
	adv4 := &net.UDPAddr{IP: net.ParseIP(adv4IP).To4(), Port: 6000}

	cand4 := []net.IP{net.ParseIP(adv4IP).To4()}
	if includeEgress {
		cand4 = append(cand4, egress4to3.IP)
	} else {
		cand4 = append(cand4, net.ParseIP(wrongIP).To4())
	}

	id4, id3 := protocol.NewPeerID(), protocol.NewPeerID()

	ph4 := New(p4[0], id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv4},
		Config{PredictionSockets: 8, PeerPortOffset: 2, SymmetricSpray: 512, ProbeIntervalMs: 1, PunchTimeoutMs: 9000})
	ph4.Conns = asPC(p4)
	ph3 := New(p3[0], id3, NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: adv3},
		Config{PredictionSockets: 1, SymmetricSpray: 512, ProbeIntervalMs: 1, PunchTimeoutMs: 9000})
	ph3.Conns = asPC(p3)
	ph4.Start()
	ph3.Start()
	defer func() {
		for _, c := range p4 {
			_ = c.Close()
		}
		for _, c := range p3 {
			_ = c.Close()
		}
		ph4.Stop()
		ph3.Stop()
	}()

	ph4.AddPeer(id3, NATInfo{Type: stun.NatPortRestrictedCone, PublicAddr: adv3})
	ph3.AddPeer(id4, NATInfo{Type: stun.NatSymmetric, PublicAddr: adv4, PublicIPs: cand4})

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		ok4, tr4 := ph4.Connected(id3)
		ok3, tr3 := ph3.Connected(id4)
		// The objective is DIRECT NAT3<->NAT4 traversal, so both sides must be
		// on a punched (not relay) transport.
		if ok4 && ok3 && tr4 == StatePunched && tr3 == StatePunched {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Logf("nat34 delivered-to-sockets=%d includeEgress=%v", atomic.LoadInt64(&delivered), includeEgress)
	return false
}

func nat4pool0IP() net.IP { return net.ParseIP("127.0.4.212").To4() }

var rotatingPool = []string{"127.0.4.212", "127.0.4.216", "127.0.4.220"}

// Positive: with the peer-direction egress IP in the candidate set, NAT3<->NAT4
// punches in both directions (destination-rotating CGNAT, the hard case).
func TestNat34PunchPositive(t *testing.T) {
	if !runNat34(t, rotatingPool, true) {
		t.Fatal("NAT3<->NAT4 must punch when candidates include the peer-direction egress IP")
	}
}

// Negative control: with the egress IP absent, the strict cone/symmetric filters
// drop everything and the punch must NOT succeed. If this passes, the model is
// too permissive and the positive result is meaningless.
func TestNat34PunchNegativeControl(t *testing.T) {
	if runNat34(t, rotatingPool, false) {
		t.Fatal("must NOT punch when the egress IP is excluded (emulator too lenient)")
	}
}

// A different network class: a symmetric NAT that keeps ONE egress IP and only
// rotates the port per destination (IP-stable). A single candidate suffices --
// this is why NAT3<->NAT4 still works when few public STUNs are reachable, as
// long as the port spray covers the range.
func TestNat34IPStableSymmetric(t *testing.T) {
	if !runNat34(t, []string{"127.0.4.216"}, true) {
		t.Fatal("IP-stable symmetric NAT must punch with a single candidate IP")
	}
}

// The "configure more STUN servers -> cover more networks" property, at scale.
// An 8-IP rotating pool:
//   - punches when the peer-direction egress IP is among the published
//     candidates (enough STUN observation points enumerated the pool);
//   - does NOT punch when they are not (under-configured for this pool).
//
// Together these show that multi-STUN candidate coverage, not the punch logic,
// is the only thing that gates large-pool CGNAT traversal on a single relay.
func TestNat34LargePoolCovered(t *testing.T) {
	pool8 := []string{
		"127.0.4.210", "127.0.4.211", "127.0.4.212", "127.0.4.213",
		"127.0.4.214", "127.0.4.215", "127.0.4.216", "127.0.4.217",
	}
	if !runNat34(t, pool8, true) {
		t.Fatal("8-IP rotating pool must punch when the egress IP is in the candidate set")
	}
}

func TestNat34LargePoolUncovered(t *testing.T) {
	pool8 := []string{
		"127.0.4.210", "127.0.4.211", "127.0.4.212", "127.0.4.213",
		"127.0.4.214", "127.0.4.215", "127.0.4.216", "127.0.4.217",
	}
	if runNat34(t, pool8, false) {
		t.Fatal("must not punch a large pool when the egress IP is not enumerated")
	}
}

// "必须实现" means reliably, not sometimes. The spray is a birthday collision
// over random ports; this runs the covered rotating-pool scenario many times
// and requires EVERY run to punch, proving convergence is dependable across
// timing seeds, not a lucky first-round hit. A single miss would mean the
// spray/pool sizing is too thin for a guaranteed traversal.
func TestNat34ConvergenceReliable(t *testing.T) {
	const trials = 12
	fails := 0
	for i := 0; i < trials; i++ {
		if !runNat34(t, rotatingPool, true) {
			fails++
		}
	}
	if fails != 0 {
		t.Fatalf("NAT3<->NAT4 punch must succeed every trial; %d/%d failed -- spray/pool too thin", fails, trials)
	}
}

// Property sweep over the egress-pool-size axis (the main way real networks
// differ): for every pool size, punch succeeds whenever the peer-direction
// egress IP is enumerated, and -- once the pool has more than one IP -- fails
// when it is not. This generalizes the point cases into "correct across the
// whole modelable pool-size space," the closest device-free proxy for
// "any network."
func TestNat34PoolSizeSweep(t *testing.T) {
	sizes := []int{1, 2, 3, 4, 6, 8}
	for _, k := range sizes {
		pool := make([]string, k)
		for i := 0; i < k; i++ {
			pool[i] = fmt.Sprintf("127.0.4.%d", 200+i)
		}
		if !runNat34(t, pool, true) {
			t.Fatalf("pool size %d: must punch when the egress IP is enumerated", k)
		}
		// Negative control only meaningful for >=3 IPs: we need an advertised IP
		// AND a distinct wrong decoy, both different from the egress. With <=2
		// IPs every non-egress choice collapses back onto the egress.
		if k >= 3 && runNat34(t, pool, false) {
			t.Fatalf("pool size %d: must NOT punch when the egress IP is excluded (too lenient)", k)
		}
	}
}
