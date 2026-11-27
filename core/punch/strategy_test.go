package punch

import (
	"net"
	"testing"

	"p2p/core/stun"
)

func addr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip).To4(), Port: port}
}

func peerInfo(t stun.NATType, pub *net.UDPAddr, step int) NATInfo {
	return NATInfo{Type: t, PublicAddr: pub, PortStep: step}
}

// The block leg fires for a hard peer with an active pool but no PortStep,
// aiming every socket at peer_port+default offset.
// A destination-rotating CGNAT only shows STUN a few of its egress IPs; the
// address it actually uses toward a given peer can be absent from that sample.
// When the peer announces its covering pool, the spray leg must widen to the
// whole block so the missing egress IP is targeted -- here the sampled set
// {114,98,110,106} collapses to 111.55.212.96/27, which also contains .102.
func TestPlanTargetsSprayCoversAnnouncedPool(t *testing.T) {
	cfg := Config{SymmetricSpray: 16, PredictionSockets: 1}
	peer := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("111.55.212.114", 7857),
		PublicIPs:  []net.IP{net.ParseIP("111.55.212.98"), net.ParseIP("111.55.212.110"), net.ParseIP("111.55.212.106")},
		PoolCIDR:   &net.IPNet{IP: net.ParseIP("111.55.212.96").To4(), Mask: net.CIDRMask(27, 32)},
	}
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)

	seen := map[string]bool{}
	for _, e := range eps {
		if e.Kind == "spray" {
			seen[e.Addr.IP.String()] = true
		}
	}
	if !seen["111.55.212.102"] {
		t.Fatalf("spray must cover the un-sampled pool address .102, got IPs %v", keys(seen))
	}
	// Sampled addresses must still be sprayed (pool widens, never replaces).
	for _, ip := range []string{"111.55.212.114", "111.55.212.98", "111.55.212.110", "111.55.212.106"} {
		if !seen[ip] {
			t.Fatalf("spray lost sampled address %s", ip)
		}
	}
}

// Without an announced pool the spray must NOT invent extra addresses: a plain
// symmetric peer with a single egress IP is sprayed only at that IP, so a
// non-rotating NAT never triggers a wide flood.
func TestPlanTargetsSprayWithoutPoolSingleIP(t *testing.T) {
	cfg := Config{SymmetricSpray: 8, PredictionSockets: 1}
	peer := NATInfo{Type: stun.NatSymmetric, PublicAddr: addr("111.55.212.114", 7857)}
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)
	for _, e := range eps {
		if e.Kind == "spray" && e.Addr.IP.String() != "111.55.212.114" {
			t.Fatalf("no pool announced but spray aimed at %s", e.Addr.IP)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPlanTargetsBlockSprayNoStep(t *testing.T) {
	cfg := Config{PredictionSockets: 5}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)

	var block []Endpoint
	for _, e := range eps {
		if e.Kind == "block" {
			block = append(block, e)
		}
	}
	if len(block) != 5 {
		t.Fatalf("want 5 block endpoints, got %d", len(block))
	}
	base := 40000 + defaultPeerPortOffset
	for i, e := range block {
		// The leg walks a window from the offset guess: N targets must cover N
		// distinct ports, not one port N times.
		if e.Addr.Port != base+i || e.Addr.IP.String() != "1.2.3.4" {
			t.Fatalf("block endpoint %d aimed at %s, want 1.2.3.4:%d", i, e.Addr, base+i)
		}
		// Step 1 fix: a cone(easy)-side probe must come from socket 0, since the
		// peer's plant mapping was aimed at socket-0's external; packets from
		// other sockets get dropped by the symmetric peer.
		if e.Socket != 0 {
			t.Fatalf("block probe must use socket 0, got socket %d", e.Socket)
		}
	}
}

// A hard (symmetric) peer that ALSO reports a PortStep must still get the
// plant+block+spray handling -- the step diagonal is an extra bet, not a
// replacement, because the diagonal assumes a stable base IP that a
// destination-rotating CGNAT does not provide. Regression guard for the gap
// where step-alignment used to be an exclusive branch and skipped the spray.
func TestPlanTargetsStepAlignedPreferred(t *testing.T) {
	cfg := Config{PredictionSockets: 4, SymmetricSpray: 12}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 118)
	eps := planTargets(NATInfo{}, peer, cfg, 0)

	var predicted, block, spray int
	for _, e := range eps {
		switch e.Kind {
		case "predicted":
			predicted++
		case "block":
			block++
		case "spray":
			spray++
		}
	}
	if predicted != 4 {
		t.Fatalf("step diagonal want 4, got %d", predicted)
	}
	if block == 0 || spray == 0 {
		t.Fatalf("hard peer with a step must STILL spray (block=%d spray=%d)", block, spray)
	}
}

// A cone-class peer with a measured step uses the step-aligned diagonal and
// does NOT trigger the hard-symmetric spray.
func TestPlanTargetsConeStepDiagonal(t *testing.T) {
	cfg := Config{PredictionSockets: 5, SymmetricSpray: 10}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("1.2.3.4", 40000), 7)
	eps := planTargets(NATInfo{Type: stun.NatFullCone}, peer, cfg, 0)
	var predicted, spray, block int
	for _, e := range eps {
		switch e.Kind {
		case "predicted":
			predicted++
		case "spray":
			spray++
		case "block":
			block++
		}
	}
	if predicted != 5 {
		t.Fatalf("cone+step want 5 diagonal, got %d", predicted)
	}
	if spray != 0 || block != 0 {
		t.Fatalf("cone peer must not trigger hard spray/block (spray=%d block=%d)", spray, block)
	}
}

// A cone peer is not sprayed by the block leg when this side is also cone;
// only the plain public address is probed.
func TestPlanTargetsConePeerNoBlock(t *testing.T) {
	cfg := Config{PredictionSockets: 5}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)
	for _, e := range eps {
		if e.Kind == "block" {
			t.Fatalf("cone-cone must not trigger block spray")
		}
	}
}

// The phone case: this side is symmetric but the peer is cone. The local
// block must still be planted, or the cone peer's aim finds no mapping.
func TestPlanTargetsBlockFiresWhenLocalHard(t *testing.T) {
	cfg := Config{PredictionSockets: 6}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("1.2.3.4", 40000), 0)
	my := NATInfo{Type: stun.NatSymmetric}
	eps := planTargets(my, peer, cfg, 0)
	block := 0
	for _, e := range eps {
		if e.Kind == "block" {
			if e.Addr.Port != 40000+defaultPeerPortOffset+block {
				t.Fatalf("block aim %s, want port %d", e.Addr, 40000+defaultPeerPortOffset+block)
			}
			block++
		}
	}
	if block != 6 {
		t.Fatalf("symmetric local side must plant 6 block endpoints, got %d", block)
	}
}

// Out-of-range offset port is skipped rather than emitting a wrapped endpoint.
func TestPlanTargetsBlockPortOutOfRange(t *testing.T) {
	cfg := Config{PredictionSockets: 5, PeerPortOffset: 65530}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{}, peer, cfg, 0)
	for _, e := range eps {
		if e.Kind == "block" {
			t.Fatalf("block endpoint should be dropped when port overflows")
		}
	}
}

// A peer that pinned a mapping on its own gateway hands us an address that needs
// no port guess. It must be in the plan, exactly as given, ahead of the guessed
// ports, and it must not be emitted for a peer that has no mapping.
func TestPlanTargetsCarvesOutGatewayMapping(t *testing.T) {
	cfg := Config{PredictionSockets: 4, SymmetricSpray: 8}
	peer := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("1.2.3.4", 40000),
		UPnPAddr:   addr("203.0.113.5", 35000),
	}
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)

	upnpAt, guessAt := -1, -1
	for i, e := range eps {
		switch e.Kind {
		case "upnp":
			upnpAt = i
		case "predicted", "block", "spray":
			if guessAt < 0 {
				guessAt = i
			}
		}
	}
	if upnpAt < 0 {
		t.Fatal("plan has no upnp target although the peer announced a mapping")
	}
	if got := eps[upnpAt].Addr.String(); got != "203.0.113.5:35000" {
		t.Fatalf("upnp target aimed at %s, want 203.0.113.5:35000", got)
	}
	if eps[upnpAt].Socket != 0 {
		t.Fatalf("upnp target uses socket %d, want 0", eps[upnpAt].Socket)
	}
	if guessAt >= 0 && upnpAt > guessAt {
		t.Fatalf("the deterministic target is ordered after the guesses (%d > %d)", upnpAt, guessAt)
	}

	none := peer
	none.UPnPAddr = nil
	for _, e := range planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, none, cfg, 0) {
		if e.Kind == "upnp" {
			t.Fatalf("plan emitted an upnp target for a peer that has none: %s", e.Addr)
		}
	}
}

// The third-octet heuristic says two hosts on 10.0.0.5/30 and 10.0.1.9/30 are on
// different links and that 172.16.5.4 with 172.16.9.8 share one. Announced
// subnets settle both, and a peer that announces nothing keeps the old behaviour.
func TestSameLANSubnetAware(t *testing.T) {
	// A /30 pair that straddles the third octet is still the same link.
	n := &net.IPNet{IP: net.ParseIP("10.0.0.4").To4(), Mask: net.CIDRMask(30, 32)}
	if !sameLAN(net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6"), []*net.IPNet{n}, nil) {
		t.Fatal("same /30 not recognised across the third octet")
	}
	// A /22 legitimately spans the third octet without being one link for our
	// purposes unless the host announces it; with the announcement it is.
	wide := &net.IPNet{IP: net.ParseIP("172.16.8.0").To4(), Mask: net.CIDRMask(22, 32)}
	if !sameLAN(net.ParseIP("172.16.9.8"), net.ParseIP("172.16.10.4"), nil, []*net.IPNet{wide}) {
		t.Fatal("announced /22 should join 172.16.9.8 and 172.16.10.4")
	}
	// An announced subnet only ever ADDS a same-LAN verdict: dropping the coarse
	// fallback for a peer that did announce something would make an old-style
	// /24 pair lose a path it has today. So a subnet that holds neither address
	// must not fire on its own, and the fallback still decides.
	small := &net.IPNet{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.CIDRMask(31, 32)}
	if sameLAN(net.ParseIP("192.168.1.4"), net.ParseIP("192.168.2.9"), []*net.IPNet{small}, nil) {
		t.Fatal("a /31 that holds neither address must not report same-LAN")
	}
	if !sameLAN(net.ParseIP("192.168.1.4"), net.ParseIP("192.168.1.9"), []*net.IPNet{small}, nil) {
		t.Fatal("the /24 fallback must survive an announcement that does not match")
	}
	// No announcement: unchanged coarse behaviour for older peers.
	if !sameLAN(net.ParseIP("192.168.1.20"), net.ParseIP("192.168.1.31"), nil, nil) {
		t.Fatal("fallback /24 comparison broke")
	}
	if sameLAN(net.ParseIP("192.168.1.20"), net.ParseIP("192.168.2.31"), nil, nil) {
		t.Fatal("different third octets must not match without an announcement")
	}
}

// A LAN target only appears when the two addresses really share a link.
func TestPlanTargetsLansUseAnnouncedSubnets(t *testing.T) {
	cfg := Config{EnableLAN: true, PredictionSockets: 1}
	peer := NATInfo{
		Type:        stun.NatPortRestrictedCone,
		PublicAddr:  addr("1.2.3.4", 40000),
		PrivateAddr: addr("10.0.0.6", 30000),
		PrivateCIDRs: []*net.IPNet{{
			IP: net.ParseIP("10.0.0.4").To4(), Mask: net.CIDRMask(30, 32),
		}},
	}
	my := NATInfo{Type: stun.NatPortRestrictedCone, PrivateAddr: addr("10.0.0.5", 30000)}
	var lan int
	for _, e := range planTargets(my, peer, cfg, 0) {
		if e.Kind == "lan" {
			lan++
		}
	}
	if lan != 1 {
		t.Fatalf("lan targets = %d, want 1 from the peer's announced /30", lan)
	}
}

// A pool wider than the per-round budget has to be walked, not re-sampled: with a
// fixed window a peer whose egress sits outside it is never reached, however many
// rounds run.
func TestSprayIPsRotatesAcrossTheAnnouncedPool(t *testing.T) {
	pool := &net.IPNet{IP: net.ParseIP("111.55.212.96").To4(), Mask: net.CIDRMask(28, 32)} // .96-.111
	info := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("111.55.212.102", 7857),
		PoolCIDR:   pool,
	}
	const budget = 4
	seen := map[string]bool{}
	for round := 0; round <= 16/budget; round++ {
		ips := info.SprayIPs(budget, round)
		if len(ips) < budget {
			t.Fatalf("round %d sprayed %d addresses, want at least %d", round, len(ips), budget)
		}
		// The observed address must lead every round; rotation never displaces it.
		if ips[0].String() != "111.55.212.102" {
			t.Fatalf("round %d leads with %s, want the observed egress", round, ips[0])
		}
		for _, ip := range ips {
			if !pool.Contains(ip) {
				t.Fatalf("round %d sprayed %s, outside the announced %s", round, ip, pool)
			}
			seen[ip.String()] = true
		}
	}
	if len(seen) != 16 {
		t.Fatalf("rotation reached %d of 16 pool addresses; window is stuck", len(seen))
	}
}

// An implausibly wide announcement is ignored rather than sprayed, so a bug on the
// announcing side cannot burn the whole budget on addresses no carrier assigns.
func TestSprayIPsIgnoresAbsurdlyWidePool(t *testing.T) {
	info := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("111.55.212.114", 7857),
		PoolCIDR:   &net.IPNet{IP: net.ParseIP("111.55.0.0").To4(), Mask: net.CIDRMask(16, 32)},
	}
	ips := info.SprayIPs(64, 0)
	if len(ips) != 1 || ips[0].String() != "111.55.212.114" {
		t.Fatalf("a /16 announcement sprayed %v, want only the sampled address", ips)
	}
}

// The tier a packet arrived on decides whether it may replace the route in use,
// so getting it wrong silently downgrades a LAN session to the public mapping.
func TestClassifyPacketTier(t *testing.T) {
	lanNet := &net.IPNet{IP: net.ParseIP("192.168.1.0").To4(), Mask: net.CIDRMask(24, 32)}
	upnp := addr("203.0.113.9", 41000)
	my := NATInfo{Type: stun.NatPortRestrictedCone, PrivateAddr: addr("192.168.1.10", 30000), PrivateCIDRs: []*net.IPNet{lanNet}}
	peer := NATInfo{
		Type:         stun.NatPortRestrictedCone,
		PublicAddr:   addr("1.2.3.4", 40000),
		PrivateAddr:  addr("192.168.1.31", 30000),
		PrivateCIDRs: []*net.IPNet{lanNet},
		UPnPAddr:     upnp,
	}
	cfg := Config{EnableLAN: true}

	cases := []struct {
		name string
		ua   *net.UDPAddr
		sock int
		want routeTier
	}{
		{"lan", peer.PrivateAddr, 0, tierLAN},
		{"upnp", upnp, 0, tierUPnP},
		{"public", peer.PublicAddr, 0, tierPublic},
		{"unrelated v4", addr("198.51.100.7", 1234), 0, tierPublic},
		{"reserved v6 socket", addr("1.2.3.4", 40000), -1, tierIPv6},
		{"v6 source", &net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: 40000}, 0, tierIPv6},
		{"no source", nil, 0, tierNone},
	}
	for _, c := range cases {
		if got := classifyPacketTier(my, peer, cfg, c.ua, c.sock); got != c.want {
			t.Errorf("%s: tier = %s, want %s", c.name, got, c.want)
		}
	}
	// A private address is only a LAN path if the shortcut is allowed; disabling it
	// must not let a LAN packet masquerade as the best route.
	if got := classifyPacketTier(my, peer, Config{}, peer.PrivateAddr, 0); got == tierLAN {
		t.Fatal("tierLAN reported with EnableLAN off")
	}
}

// A peer on a multi-homed host announces every interface; only the subnet we
// actually share becomes a LAN target, and it appears once.
func TestPlanTargetsLANUsesEveryAnnouncedInterface(t *testing.T) {
	ourNet := &net.IPNet{IP: net.ParseIP("10.10.0.0").To4(), Mask: net.CIDRMask(24, 32)}
	my := NATInfo{Type: stun.NatPortRestrictedCone, PrivateAddr: addr("10.10.0.5", 30000), PrivateCIDRs: []*net.IPNet{ourNet}}
	peer := NATInfo{
		Type:              stun.NatPortRestrictedCone,
		PublicAddr:        addr("1.2.3.4", 40000),
		PrivateAddr:       addr("172.16.9.9", 30000), // a different network we cannot reach
		ExtraPrivateAddrs: []*net.UDPAddr{addr("10.10.0.31", 30000)},
	}
	var lan []string
	for _, e := range planTargets(my, peer, Config{EnableLAN: true, PredictionSockets: 1}, 0) {
		if e.Kind == "lan" {
			lan = append(lan, e.Addr.String())
		}
	}
	if len(lan) != 1 || lan[0] != "10.10.0.31:30000" {
		t.Fatalf("lan targets %v, want exactly the shared subnet's address", lan)
	}
}

func countKind(eps []Endpoint, kind string) []Endpoint {
	var out []Endpoint
	for _, e := range eps {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// The cone side facing a hard peer (the Windows case): a wide spray window is
// emitted at the peer's public IP from the primary socket only. This is the
// birthday leg that connects a cellular CGNAT, which the block offset cannot.
func TestPlanTargetsConeSpraysHardPeer(t *testing.T) {
	cfg := Config{PredictionSockets: 5, SymmetricSpray: 64}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)

	spray := countKind(eps, "spray")
	if len(spray) != 64 {
		t.Fatalf("want 64 spray endpoints, got %d", len(spray))
	}
	seen := map[int]bool{}
	for _, e := range spray {
		if e.Addr.IP.String() != "1.2.3.4" {
			t.Fatalf("spray endpoint off the peer IP: %s", e.Addr)
		}
		if e.Socket != 0 {
			t.Fatalf("spray must use the primary socket, got %d", e.Socket)
		}
		if seen[e.Addr.Port] {
			t.Fatalf("duplicate spray port %d", e.Addr.Port)
		}
		seen[e.Addr.Port] = true
	}
	// Cone local side must not plant (it has no random port to hide).
	if p := countKind(eps, "plant"); len(p) != 0 {
		t.Fatalf("cone side should not plant, got %d", len(p))
	}
}

// The hard side (the phone case) facing a cone peer plants every pool socket at
// the peer's advertised public address -- NOT the offset port -- so the peer's
// blind spray has mappings to collide with.
func TestPlanTargetsHardSidePlants(t *testing.T) {
	cfg := Config{PredictionSockets: 6, SymmetricSpray: 32}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("1.2.3.4", 40000), 0)
	my := NATInfo{Type: stun.NatSymmetric}
	eps := planTargets(my, peer, cfg, 0)

	plant := countKind(eps, "plant")
	if len(plant) != 5 { // sockets 1..5; socket 0 is covered by the public target
		t.Fatalf("want 5 plant endpoints, got %d", len(plant))
	}
	for _, e := range plant {
		if e.Addr.String() != "1.2.3.4:40000" {
			t.Fatalf("plant must aim at advertised public addr, got %s", e.Addr)
		}
	}
	// Cone peer means this hard side does not spray.
	if s := countKind(eps, "spray"); len(s) != 0 {
		t.Fatalf("cone peer should not trigger local spray, got %d", len(s))
	}
}

// Both sides hard: plant our own mappings and still spray the peer, since each
// side is blind to the other's random public ports.
func TestPlanTargetsBothHardPlantAndSpray(t *testing.T) {
	cfg := Config{PredictionSockets: 4, SymmetricSpray: 40}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	my := NATInfo{Type: stun.NatSymmetric}
	eps := planTargets(my, peer, cfg, 0)
	if len(countKind(eps, "plant")) != 3 {
		t.Fatalf("hard side should plant 3 extra sockets")
	}
	if len(countKind(eps, "spray")) != 40 {
		t.Fatalf("hard peer should be sprayed with 40 ports")
	}
}

// The Windows↔phone reality: the hard peer rotates its public IP per
// destination, so the cone side must spray the whole candidate set, not just
// the single server-reported address.
func TestPlanTargetsSprayCoversCandidateIPs(t *testing.T) {
	cfg := Config{PredictionSockets: 5, SymmetricSpray: 50}
	peer := peerInfo(stun.NatSymmetric, addr("223.104.77.212", 2501), 0)
	peer.PublicIPs = []net.IP{net.ParseIP("223.104.77.220"), net.ParseIP("223.104.77.212")} // dup included
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)

	perIP := map[string]int{}
	for _, e := range countKind(eps, "spray") {
		perIP[e.Addr.IP.String()]++
	}
	// Two distinct candidate IPs (dup dropped), each with the full 50-port window.
	if len(perIP) != 2 {
		t.Fatalf("spray should cover 2 distinct candidate IPs, got %v", perIP)
	}
	for ip, c := range perIP {
		if c != 50 {
			t.Fatalf("ip %s got %d spray ports, want 50", ip, c)
		}
	}
	if perIP["223.104.77.212"] != 50 || perIP["223.104.77.220"] != 50 {
		t.Fatalf("expected spray at both advertised + observed IPs, got %v", perIP)
	}
}

// The multi-IP spray (the leg that cracks a destination-rotating CGNAT) must
// fire even with the socket pool disabled -- it only uses the primary socket.
// Regression guard: previously the whole hard branch was gated on
// PredictionSockets > 1, so a single-socket config silently lost the spray.
func TestPlanTargetsSprayWithoutPool(t *testing.T) {
	cfg := Config{PredictionSockets: 1, SymmetricSpray: 30}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)
	spray := countKind(eps, "spray")
	if len(spray) != 30 {
		t.Fatalf("spray must run without a pool: got %d, want 30", len(spray))
	}
	if len(countKind(eps, "block")) != 0 || len(countKind(eps, "plant")) != 0 {
		t.Fatal("pool legs (block/plant) must be empty when PredictionSockets <= 1")
	}
}

// A peer we could not classify must fail safe into the aggressive hard path --
// an unknown/blocked peer gets the multi-IP spray, not the cone fast path that
// silently drops the traversal a symmetric NAT would need. Regression guard for
// "any network" where STUN classification can be ambiguous.
func TestPlanTargetsUnknownFailsafeHard(t *testing.T) {
	cfg := Config{PredictionSockets: 5, SymmetricSpray: 40}
	for _, ty := range []stun.NATType{stun.NatUnknown, stun.NatBlocked, stun.NatUnmeasurable} {
		peer := peerInfo(ty, addr("1.2.3.4", 40000), 0)
		eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg, 0)
		if len(countKind(eps, "spray")) == 0 {
			t.Fatalf("peer %s must trigger spray (fail-safe hard), got none", ty)
		}
	}
}

// distinctPorts yields unique, in-range ports and is capped at the range size.
func TestDistinctPortsUnique(t *testing.T) {
	ports := distinctPorts(1000)
	if len(ports) != 1000 {
		t.Fatalf("want 1000 ports, got %d", len(ports))
	}
	seen := map[int]bool{}
	for _, p := range ports {
		if p < 1024 || p > 65535 {
			t.Fatalf("port %d out of spray range", p)
		}
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
	if got := len(distinctPorts(70000)); got != 64512 {
		t.Fatalf("spray count should cap at range size, got %d", got)
	}
	if distinctPorts(0) != nil {
		t.Fatalf("0 ports should be nil")
	}
}
