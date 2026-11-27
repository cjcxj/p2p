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

func countKind(eps []Endpoint, kind string) []Endpoint {
	var out []Endpoint
	for _, e := range eps {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// NAT3 (Cone) facing NAT4 (Symmetric) must send ALL probes on Socket 0 (whose
// public port NAT4 learned), never Socket 1..N which NAT4 drops.
func TestPlanTargetsEasyFacingHardUsesSocketZeroOnly(t *testing.T) {
	cfg := Config{PredictionSockets: 128, SymmetricSpray: 256}
	peer := peerInfo(stun.NatSymmetric, addr("198.51.100.2", 40000), 118)
	peer.PortBlockMin = 40000
	peer.PortBlockMax = 40400
	peer.PortPreserve = true
	peer.PortPreserveOffset = 0
	peer.PrivateAddr = addr("10.0.0.5", 30000)

	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)

	for _, e := range eps {
		if e.Kind == "plant" {
			t.Fatalf("easy NAT3 side must not emit plant endpoints")
		}
		if e.Socket != 0 {
			t.Fatalf("easy NAT3 side probe kind=%s used socket %d, MUST be socket 0", e.Kind, e.Socket)
		}
	}
	if len(countKind(eps, "predicted")) == 0 {
		t.Fatal("expected predicted step targets")
	}
	if len(countKind(eps, "preserve")) == 0 {
		t.Fatal("expected port-preserve targets alongside predicted")
	}
	if len(countKind(eps, "pba")) == 0 {
		t.Fatal("expected PBA block targets alongside predicted (no mutual exclusion)")
	}
	if len(countKind(eps, "spray")) == 0 {
		t.Fatal("expected birthday-attack spray alongside step/pba (no mutual exclusion)")
	}
}

// NAT4 (Symmetric) facing NAT3 (Cone) plants its pool sockets toward NAT3's
// advertised public address so NAT3's spray/predicted probes can hit them.
func TestPlanTargetsHardSidePlantsTowardCone(t *testing.T) {
	cfg := Config{PredictionSockets: 16, SymmetricSpray: 64}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("203.0.113.10", 50000), 0)
	my := NATInfo{Type: stun.NatSymmetric}
	eps := planTargets(my, peer, cfg)

	plant := countKind(eps, "plant")
	if len(plant) != 15 { // sockets 1..15 (socket 0 covered by public)
		t.Fatalf("want 15 plant endpoints, got %d", len(plant))
	}
	seenSock := map[int]bool{}
	for _, e := range plant {
		if e.Addr.String() != "203.0.113.10:50000" {
			t.Fatalf("plant must aim at peer public addr, got %s", e.Addr)
		}
		seenSock[e.Socket] = true
	}
	for k := 1; k < 16; k++ {
		if !seenSock[k] {
			t.Fatalf("missing plant socket %d", k)
		}
	}
	if len(countKind(eps, "spray")) != 0 {
		t.Fatalf("hard peer toward cone should not spray")
	}
}

// Both sides hard (NAT4<->NAT4): local side plants pool sockets AND sprays peer.
func TestPlanTargetsBothHardPlantAndSpray(t *testing.T) {
	cfg := Config{PredictionSockets: 8, SymmetricSpray: 40}
	peer := peerInfo(stun.NatSymmetric, addr("198.51.100.2", 40000), 0)
	my := NATInfo{Type: stun.NatSymmetric}
	eps := planTargets(my, peer, cfg)

	if len(countKind(eps, "plant")) != 7 {
		t.Fatalf("hard side should plant 7 extra sockets, got %d", len(countKind(eps, "plant")))
	}
	if len(countKind(eps, "spray")) != 40 {
		t.Fatalf("hard peer should be sprayed with 40 ports, got %d", len(countKind(eps, "spray")))
	}
}

// Destination-rotating CGNAT: spray covers all distinct candidate IPs.
func TestPlanTargetsSprayCoversCandidateIPs(t *testing.T) {
	cfg := Config{PredictionSockets: 16, SymmetricSpray: 50}
	peer := peerInfo(stun.NatSymmetric, addr("223.104.77.212", 2501), 0)
	peer.PublicIPs = []net.IP{net.ParseIP("223.104.77.220"), net.ParseIP("223.104.77.212")}
	peer.ObservedMappings = []*net.UDPAddr{addr("223.104.77.224", 2600)}
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)

	perIP := map[string]int{}
	for _, e := range countKind(eps, "spray") {
		if e.Socket != 0 {
			t.Fatalf("spray must use socket 0, got %d", e.Socket)
		}
		perIP[e.Addr.IP.String()]++
	}
	if len(perIP) != 3 {
		t.Fatalf("spray should cover 3 distinct candidate IPs, got %v", perIP)
	}
	for ip, c := range perIP {
		if c != 50 {
			t.Fatalf("ip %s got %d spray ports, want 50", ip, c)
		}
	}
}

// PortDeck draws without replacement across rounds until all unprivileged ports
// are exhausted.
func TestPortDeckWithoutReplacement(t *testing.T) {
	deck := newPortDeck(nil)
	seen := map[int]bool{}
	for round := 0; round < 20; round++ {
		batch := deck.next(256)
		if len(batch) != 256 {
			t.Fatalf("batch len = %d, want 256", len(batch))
		}
		for _, p := range batch {
			if p < 1024 || p > 65535 {
				t.Fatalf("out-of-range port %d", p)
			}
			if seen[p] {
				t.Fatalf("duplicate port %d drawn before deck exhausted (round %d)", p, round)
			}
			seen[p] = true
		}
	}
}

// Subnet-aware sameLAN matches custom /22 subnets as well as default /24.
func TestSameLANSubnetAware(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.10.0.0/22")
	a := net.ParseIP("10.10.1.5").To4()
	b := net.ParseIP("10.10.2.8").To4()
	if sameLAN(a, b, nil, nil) {
		t.Fatal("without CIDR, /24 should not match different third octet")
	}
	if !sameLAN(a, b, []*net.IPNet{cidr}, nil) {
		t.Fatal("with /22 CIDR, 10.10.1.5 and 10.10.2.8 should be same LAN")
	}
}

func TestPlanTargetsFailSafeOnUnknownAndSinglePool(t *testing.T) {
	for _, natType := range []stun.NATType{stun.NatUnknown, stun.NatBlocked} {
		peer := peerInfo(natType, addr("198.51.100.2", 40000), 0)
		// Even with PredictionSockets=1 (pool disabled), easy side still sprays on Socket 0.
		eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, Config{
			PredictionSockets: 1,
			SymmetricSpray:    32,
		})
		spray := countKind(eps, "spray")
		if len(spray) != 32 {
			t.Fatalf("nat=%s with pool=1: expected 32 spray endpoints, got %d", natType, len(spray))
		}
		for _, e := range spray {
			if e.Socket != 0 {
				t.Fatalf("spray must use socket 0, got %d", e.Socket)
			}
		}
	}
}

func TestSprayIPsWholePoolAndRotation(t *testing.T) {
	_, pool27, _ := net.ParseCIDR("111.55.212.96/27")
	info := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("111.55.212.114", 7857),
		PublicIPs:  []net.IP{net.ParseIP("111.55.212.98")},
		PoolCIDR:   pool27,
	}
	ips := info.SprayIPs(64, 0)
	got := map[string]bool{}
	for _, ip := range ips {
		got[ip.String()] = true
	}
	if !got["111.55.212.102"] || !got["111.55.212.114"] {
		t.Fatalf("expected un-sampled .102 and primary .114 in /27 expansion, got %d IPs", len(got))
	}

	// Larger /24 pool (256 IPs) with max=64 rotates cleanly across 4 rounds to cover all 256 IPs.
	_, pool24, _ := net.ParseCIDR("198.51.100.0/24")
	wide := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("198.51.100.1", 5000),
		PoolCIDR:   pool24,
	}
	covered := map[string]bool{}
	for round := 0; round < 4; round++ {
		for _, ip := range wide.SprayIPs(64, round) {
			covered[ip.String()] = true
		}
	}
	if len(covered) != 256 {
		t.Fatalf("expected 4 rounds of 64 to cover all 256 hosts in /24, covered %d", len(covered))
	}
}

func TestWeightedSprayDoesNotDiluteObservedIPs(t *testing.T) {
	_, pool26, _ := net.ParseCIDR("198.51.100.0/26")
	peer := NATInfo{
		Type:       stun.NatSymmetric,
		PublicAddr: addr("198.51.100.5", 40000),
		PoolCIDR:   pool26,
	}
	eps := planTargetsWithDeck(NATInfo{Type: stun.NatPortRestrictedCone}, peer, Config{
		PredictionSockets: 128,
		SymmetricSpray:    256,
		SprayIPMax:        64,
	}, newPortDeck(nil), 0)

	spray := countKind(eps, "spray")
	perIP := map[string]int{}
	for _, e := range spray {
		perIP[e.Addr.IP.String()]++
	}
	if perIP["198.51.100.5"] != 256 {
		t.Fatalf("primary observed IP got %d spray ports, want full 256", perIP["198.51.100.5"])
	}
	if len(perIP) != 64 {
		t.Fatalf("expected all 64 /26 IPs to receive probes, got %d", len(perIP))
	}
	for ip, cnt := range perIP {
		if ip != "198.51.100.5" && cnt < 128 {
			t.Fatalf("cold pool IP %s got only %d ports, want >= 128 floor for unsampled rescue", ip, cnt)
		}
	}
	// First 256 spray endpoints must target the hot observed IP before cold pool IPs.
	for i := 0; i < 256; i++ {
		if spray[i].Addr.IP.String() != "198.51.100.5" {
			t.Fatalf("spray[%d] = %s, expected hot observed IP prioritized first", i, spray[i].Addr.IP)
		}
	}
	if len(spray) >= 10000 {
		t.Fatalf("weighted spray should substantially reduce packet load vs 16384 equal-256 (got %d)", len(spray))
	}
}

func TestStaggeredPlantRefresh(t *testing.T) {
	cfg := Config{PredictionSockets: 128, SymmetricSpray: 64}
	my := NATInfo{Type: stun.NatSymmetric, PublicAddr: addr("198.51.100.2", 40000)}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("203.0.113.10", 50000), 0)

	// Round 0 and 1 plant the full pool.
	for r := 0; r < 2; r++ {
		p := countKind(planTargetsWithDeck(my, peer, cfg, nil, r), "plant")
		if len(p) != 127 {
			t.Fatalf("round %d: want full 127 plant sockets, got %d", r, len(p))
		}
	}

	// Round 2+ refreshes only a small rotating batch per round and covers all 127 across rounds.
	seen := map[int]bool{}
	for r := 2; r < 20; r++ {
		p := countKind(planTargetsWithDeck(my, peer, cfg, nil, r), "plant")
		if len(p) == 0 || len(p) > 32 {
			t.Fatalf("round %d: want staggered batch in [1..32], got %d", r, len(p))
		}
		for _, e := range p {
			seen[e.Socket] = true
		}
	}
	if len(seen) != 127 {
		t.Fatalf("expected staggered rotation to cover all 127 sockets, covered %d", len(seen))
	}
}

func TestAlignPBABoundsSnapsToBRASBlocks(t *testing.T) {
	// Narrow sample near the top of a 256-port block [49408..49663] (193*256).
	lo, hi := alignPBABounds(49640, 49660)
	if lo > 49408 || hi < 49663 {
		t.Fatalf("expected 256-block coverage [49408..49663], got %d..%d", lo, hi)
	}
	// Wider sample spanning into a 512-port block [49152..49663] (96*512).
	lo2, hi2 := alignPBABounds(49200, 49660)
	if lo2 > 49152 || hi2 < 49663 {
		t.Fatalf("expected 512-block coverage [49152..49663], got %d..%d", lo2, hi2)
	}
}

func TestClassifyPacketTierOrdering(t *testing.T) {
	my := NATInfo{
		PrivateAddr: addr("192.168.1.10", 5000),
		IPv6Addr:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 6000},
	}
	peer := NATInfo{
		PublicAddr:  addr("203.0.113.5", 40000),
		PrivateAddr: addr("192.168.1.20", 5001),
		UPnPAddr:    addr("203.0.113.5", 35000),
		IPv6Addr:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6001},
	}
	cfg := Config{EnableLAN: true}

	tLAN := classifyPacketTier(my, peer, cfg, addr("192.168.1.20", 5001), 0)
	tIPv6 := classifyPacketTier(my, peer, cfg, peer.IPv6Addr, -1)
	tUPnP := classifyPacketTier(my, peer, cfg, peer.UPnPAddr, 0)
	tPub := classifyPacketTier(my, peer, cfg, peer.PublicAddr, 0)

	if !(tLAN > tIPv6 && tIPv6 > tUPnP && tUPnP > tPub) {
		t.Fatalf("unexpected tier ordering: lan=%d ipv6=%d upnp=%d public=%d", tLAN, tIPv6, tUPnP, tPub)
	}
	// When EnableLAN is false, private LAN addresses must not win as LAN.
	if got := classifyPacketTier(my, peer, Config{EnableLAN: false}, addr("192.168.1.20", 5001), 0); got != tierPublic {
		t.Fatalf("expected tierPublic when EnableLAN=false, got %s", got)
	}
}

