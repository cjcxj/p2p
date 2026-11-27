package p2p

import (
	"encoding/json"
	"net"
	"testing"

	"p2p/core/protocol"
	"p2p/core/stun"
)

// The observation-point IPs travel in the same string field a signalling server
// that forwards Candidate verbatim will hand back untouched.
func TestCandidatePublicAddrSmuggling(t *testing.T) {
	primary, extras := splitCandidateAddr("223.104.77.212:2501,223.104.77.220,111.206.174.2")
	if primary != "223.104.77.212:2501" {
		t.Fatalf("primary parsed as %q", primary)
	}
	if len(extras) != 2 || extras[0] != "223.104.77.220" || extras[1] != "111.206.174.2" {
		t.Fatalf("extras wrong: %#v", extras)
	}

	// A plain "ip:port" from an old peer must still parse with no extras.
	one, none := splitCandidateAddr("1.2.3.4:5000")
	if one != "1.2.3.4:5000" || none != nil {
		t.Fatalf("single addr split wrong: %q %#v", one, none)
	}
}

func TestCandidateToNATDecodesExtras(t *testing.T) {
	c := &protocol.Candidate{
		NATType:    "symmetric",
		PublicAddr: "223.104.77.212:2501,223.104.77.220",
		PortStep:   0,
	}
	info, err := candidateToNAT(c)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.PublicAddr == nil || info.PublicAddr.Port != 2501 || info.PublicAddr.IP.String() != "223.104.77.212" {
		t.Fatalf("primary addr decode wrong: %v", info.PublicAddr)
	}
	if len(info.PublicIPs) != 1 || info.PublicIPs[0].String() != "223.104.77.220" {
		t.Fatalf("observed IP not decoded: %#v", info.PublicIPs)
	}
}

// End-to-end at the wire boundary: a real multi-IP candidate string (exactly
// what the publisher writes into PublicAddr, carried verbatim by the old
// signalling server) must decode into the full candidate IP SET that the spray
// leg aims at -- deduping the advertised address against the observation list.
// This closes the "configurable multi-STUN -> published wire -> spray targets"
// chain that the punch-layer emulator feeds by hand.
func TestCandidateWireToSprayTargets(t *testing.T) {
	// advertised .212 also appears in the observation list -> must dedupe to 3.
	c := &protocol.Candidate{
		NATType:    "symmetric",
		PublicAddr: "223.104.77.212:2501,223.104.77.212,223.104.77.216,223.104.77.220",
	}
	info, err := candidateToNAT(c)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cands := info.CandidateIPs()
	seen := map[string]bool{}
	for _, ip := range cands {
		seen[ip.String()] = true
	}
	if len(cands) != 3 {
		t.Fatalf("want 3 distinct spray target IPs (advertised + 2 unique observed, deduped), got %v", cands)
	}
	for _, want := range []string{"223.104.77.212", "223.104.77.216", "223.104.77.220"} {
		if !seen[want] {
			t.Fatalf("spray target set missing %s: %v", want, cands)
		}
	}
}

// The Unicom failure mode: STUN shows only .98/.106/.110/.114 but the carrier
// egress used toward the cone peer is .102 -- absent from the sample. The
// covering prefix of the sampled set (.96/27) DOES contain it, so advertising
// that pool and expanding it on the receiving side is what closes the hole.
func TestCoveringPrefixFromSampledCGNAT(t *testing.T) {
	det := &stun.Detection{
		MappedAddr:  &net.UDPAddr{IP: net.ParseIP("111.55.212.114"), Port: 7857},
		ObservedIPs: []net.IP{net.ParseIP("111.55.212.98"), net.ParseIP("111.55.212.110"), net.ParseIP("111.55.212.106")},
	}
	pool := coveringPrefix(det)
	if pool == nil {
		t.Fatal("no pool derived from a clustered CGNAT sample")
	}
	if ones, _ := pool.Mask.Size(); ones != 27 {
		t.Fatalf("want /27 covering block, got /%d (%s)", ones, pool)
	}
	if !pool.Contains(net.ParseIP("111.55.212.102")) {
		t.Fatalf("derived pool %s does not contain the real egress .102", pool)
	}
}

// Single-address peers must not announce a pool (nothing to expand), and a
// sample too spread out to be one carrier block must be rejected rather than
// advertised as a huge range.
func TestCoveringPrefixGuards(t *testing.T) {
	single := &stun.Detection{MappedAddr: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1}}
	if coveringPrefix(single) != nil {
		t.Fatal("single address should not produce a pool")
	}
	spread := &stun.Detection{
		MappedAddr:  &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1},
		ObservedIPs: []net.IP{net.ParseIP("200.1.1.1")},
	}
	if coveringPrefix(spread) != nil {
		t.Fatal("widely separated candidates should not produce a pool")
	}
}

// Full wire round-trip for the rotating-pool case: the publisher smuggles the
// covering prefix as a CIDR token after the sampled IPs; the peer decodes it
// and the spray target set gains the previously-missing .102 while keeping the
// sampled addresses. An old peer would drop the CIDR token harmlessly.
func TestCandidateWireToPoolSpray(t *testing.T) {
	c := &protocol.Candidate{
		NATType:    "symmetric",
		PublicAddr: "111.55.212.114:7857,111.55.212.98,111.55.212.110,111.55.212.106,111.55.212.96/27",
	}
	info, err := candidateToNAT(c)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.PoolCIDR == nil || info.PoolCIDR.String() != "111.55.212.96/27" {
		t.Fatalf("pool CIDR not decoded: %#v", info.PoolCIDR)
	}
	// The sampled set alone does NOT contain .102.
	found := false
	for _, ip := range info.CandidateIPs() {
		if ip.String() == "111.55.212.102" {
			found = true
		}
	}
	if found {
		t.Fatal("CandidateIPs should only reflect sampled addresses")
	}
	// With the pool expanded the spray covers .102.
	spray := map[string]bool{}
	for _, ip := range info.SprayIPs(64) {
		spray[ip.String()] = true
	}
	if !spray["111.55.212.102"] {
		t.Fatalf("pool expansion missed .102; got %d IPs", len(spray))
	}
	if !spray["111.55.212.114"] {
		t.Fatalf("pool expansion must still keep the advertised address")
	}
}

// The full PRODUCTION path, end to end, with nothing hand-built: run the real
// buildCandidate on a real Detection (the Unicom field sample), push the
// resulting Candidate through the same json.Marshal the signalling frame uses
// (the server forwards the message verbatim), decode it on the receiving side,
// and confirm the cone peer's spray set gains the never-observed .102. This is
// the closest device-free reproduction of the live 111.55 NAT3<->NAT4 rescue,
// so a regression anywhere in publish -> wire -> decode -> spray is caught here
// rather than only on hardware.
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

	// Serialize exactly like core/signaling.WriteMsg does.
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
		t.Fatalf("buildCandidate did not advertise an egress pool through the wire: PublicAddr=%q", m.Candidate.PublicAddr)
	}
	// The sampled candidate set alone must NOT contain .102.
	for _, ip := range info.CandidateIPs() {
		if ip.String() == "111.55.212.102" {
			t.Fatal("sampled set unexpectedly contains the un-observed .102")
		}
	}
	// After whole-pool expansion the spray reaches .102.
	reached := false
	for _, ip := range info.SprayIPs(0) {
		if ip.String() == "111.55.212.102" {
			reached = true
			break
		}
	}
	if !reached {
		t.Fatalf("production spray set missed the un-sampled egress .102 (pool %s)", info.PoolCIDR)
	}
}

// A gateway mapping the sender pinned for us has to survive the trip to the
// peer's punching plan, including its port -- which is why it rides its own field
// instead of the bare-IP list in PublicAddr.
func TestCandidateCarriesGatewayMapping(t *testing.T) {
	det := &stun.Detection{
		NATType:    stun.NatPortRestrictedCone,
		MappedAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.44"), Port: 59804},
		LocalAddr:  &net.UDPAddr{IP: net.ParseIP("192.168.1.45"), Port: 30000},
		UPnPAddr:   &net.UDPAddr{IP: net.ParseIP("203.0.113.44"), Port: 41000},
	}
	s := &Session{det: det}

	b, err := json.Marshal(protocol.Message{Type: protocol.MsgCandidate, Candidate: s.buildCandidate()})
	if err != nil {
		t.Fatalf("wire marshal: %v", err)
	}
	var m protocol.Message
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("wire unmarshal: %v", err)
	}
	if m.Candidate.UPnPAddr != "203.0.113.44:41000" {
		t.Fatalf("wire carries upnp_addr %q, want 203.0.113.44:41000", m.Candidate.UPnPAddr)
	}

	info, err := candidateToNAT(m.Candidate)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.UPnPAddr == nil || info.UPnPAddr.Port != 41000 {
		t.Fatalf("decoded NATInfo lost the mapping: %v", info.UPnPAddr)
	}

	// A peer that never got a mapping must not put an empty target in the plan.
	plain := &Session{det: &stun.Detection{
		NATType:    stun.NatPortRestrictedCone,
		MappedAddr: det.MappedAddr,
		LocalAddr:  det.LocalAddr,
	}}
	q, err := candidateToNAT(plain.buildCandidate())
	if err != nil {
		t.Fatalf("decode plain: %v", err)
	}
	if q.UPnPAddr != nil {
		t.Fatalf("absent mapping decoded as %v", q.UPnPAddr)
	}
}
