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
func TestPlanTargetsBlockSprayNoStep(t *testing.T) {
	cfg := Config{PredictionSockets: 5}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)

	var block []Endpoint
	for _, e := range eps {
		if e.Kind == "block" {
			block = append(block, e)
		}
	}
	if len(block) != 5 {
		t.Fatalf("want 5 block endpoints, got %d", len(block))
	}
	wantPort := 40000 + defaultPeerPortOffset
	seenSock := map[int]bool{}
	for _, e := range block {
		if e.Addr.Port != wantPort || e.Addr.IP.String() != "1.2.3.4" {
			t.Fatalf("block endpoint aimed at %s, want 1.2.3.4:%d", e.Addr, wantPort)
		}
		seenSock[e.Socket] = true
	}
	for k := 0; k < 5; k++ {
		if !seenSock[k] {
			t.Fatalf("block spray must cover socket %d", k)
		}
	}
}

// A measured PortStep takes precedence and yields the step-aligned diagonal
// instead of the fixed-offset block.
func TestPlanTargetsStepAlignedPreferred(t *testing.T) {
	cfg := Config{PredictionSockets: 4}
	peer := peerInfo(stun.NatSymmetric, addr("1.2.3.4", 40000), 118)
	eps := planTargets(NATInfo{}, peer, cfg)

	var predicted, block int
	for _, e := range eps {
		switch e.Kind {
		case "predicted":
			predicted++
		case "block":
			block++
		}
	}
	if predicted != 4 || block != 0 {
		t.Fatalf("with PortStep want 4 predicted + 0 block, got %d/%d", predicted, block)
	}
}

// A cone peer is not sprayed by the block leg when this side is also cone;
// only the plain public address is probed.
func TestPlanTargetsConePeerNoBlock(t *testing.T) {
	cfg := Config{PredictionSockets: 5}
	peer := peerInfo(stun.NatPortRestrictedCone, addr("1.2.3.4", 40000), 0)
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)
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
	eps := planTargets(my, peer, cfg)
	block := 0
	for _, e := range eps {
		if e.Kind == "block" {
			block++
			if e.Addr.Port != 40000+defaultPeerPortOffset {
				t.Fatalf("block aim %s", e.Addr)
			}
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
	eps := planTargets(NATInfo{}, peer, cfg)
	for _, e := range eps {
		if e.Kind == "block" {
			t.Fatalf("block endpoint should be dropped when port overflows")
		}
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
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)

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
	eps := planTargets(my, peer, cfg)

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
	eps := planTargets(my, peer, cfg)
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
	eps := planTargets(NATInfo{Type: stun.NatPortRestrictedCone}, peer, cfg)

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
