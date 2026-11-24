package punch

import (
	"math/rand"
	"net"

	"p2p/core/stun"
)

// defaultPeerPortOffset mirrors n4's "-o 20": every pool socket aims at
// peer_port+offset, betting the NAT preserves the local port into the public
// one, so the peer's own block spray lands inside this socket's public port.
const defaultPeerPortOffset = 20

// defaultSymmetricSpray is how many random ports the easy side fires at a hard
// peer's public IP each round -- the EasyTier "hard-sym" birthday leg that
// works when the peer's NAT randomizes the per-socket public port.
const defaultSymmetricSpray = 1024

// Endpoint is one address the punch engine will probe.
type Endpoint struct {
	Addr   *net.UDPAddr
	Kind   string // "lan","public","predicted","block","plant","spray","relay"
	Order  int
	Socket int // index into Punch.Conns; 0 = primary
}

// NATInfo describes one side's reachability from the other side's
// perspective.
type NATInfo struct {
	Type        stun.NATType
	PublicAddr  *net.UDPAddr
	PrivateAddr *net.UDPAddr
	PortDelta   int
	PortStep    int
	RelayAddr   *net.UDPAddr
	// PublicIPs are additional distinct public addresses this peer was seen at
	// across multiple STUN observation points (a destination-rotating CGNAT).
	// Empty for ordinary NATs; the spray leg aims at all of them plus
	// PublicAddr.IP.
	PublicIPs []net.IP
}

// CandidateIPs returns every public IPv4 address the peer might be reached at:
// its advertised PublicAddr.IP first, then any observation-point addresses, with
// duplicates removed. A CGNAT that rotates egress IP per destination is only
// punchable if the spray covers the address it happens to use toward us.
func (n NATInfo) CandidateIPs() []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		if seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	if n.PublicAddr != nil {
		add(n.PublicAddr.IP)
	}
	for _, ip := range n.PublicIPs {
		add(ip)
	}
	return out
}

// Config tunes the punch engine.
type Config struct {
	// PortPrediction enables port-range probing for symmetric NATs.
	PortPrediction bool
	// RelayFallback enables the relay endpoint as a last resort.
	RelayFallback bool
	// EnableLAN allows probing the private address for same-LAN peers.
	EnableLAN bool
	// PredictionRange is the number of ports probed on each side of the
	// predicted symmetric mapping (default 4).
	PredictionRange int
	// ProbeInterval is the delay between probe bursts (default 200ms).
	ProbeIntervalMs int
	// PunchTimeout is how long to punch before trying the relay.
	PunchTimeoutMs int
	// PredictionSockets is the number of source sockets in the spray pool
	// (default 0 = no pool; 1 = primary only). Values > 1 bind a contiguous
	// local port block and drive both the step-aligned prediction leg and the
	// hard-symmetric plant/block legs. It needs no peer PortStep for the
	// plant/block/spray legs, so it reaches a cellular CGNAT the step path
	// cannot.
	PredictionSockets int
	// PeerPortOffset shifts the deterministic block spray off the peer's
	// reported public port. It assumes the NAT roughly preserves the local
	// source port (n4's "-o"), so it needs no per-binding step measurement
	// and is the fallback when PortStep is unknown. 0 = defaultPeerPortOffset.
	PeerPortOffset int
	// SymmetricSpray is how many random ports the EASY side (cone NAT) fires
	// at the hard peer's public IP each round when the peer reports no usable
	// PortStep. Paired with the hard side's PLANT leg (all pool sockets aimed
	// at this side's advertised address) it forms EasyTier's hard-sym
	// birthday attack, the path that works against cellular CGNAT. 0 = use
	// defaultSymmetricSpray (1024).
	SymmetricSpray int
	// OnLog, when set, receives verbose hole-punching flow messages.
	OnLog func(format string, args ...interface{})
}

// planTargets builds the ordered list of endpoints to probe for the remote
// peer, encoding the NAT combination strategy matrix. The same matrix is
// applied symmetrically by both sides (simultaneous probing).
func planTargets(my NATInfo, peer NATInfo, cfg Config) []Endpoint {
	var eps []Endpoint
	order := 0

	// LAN shortcut: same private network.
	if cfg.EnableLAN && peer.PrivateAddr != nil && my.PrivateAddr != nil &&
		peer.PrivateAddr.IP != nil && my.PrivateAddr.IP != nil {
		pe := peer.PrivateAddr.IP.To4()
		me := my.PrivateAddr.IP.To4()
		if pe != nil && me != nil && sameLAN(pe, me) {
			eps = append(eps, Endpoint{Addr: peer.PrivateAddr, Kind: "lan", Order: order})
			order++
		}
	}

	// Public address: always probed. Works for every cone combination and
	// often for symmetric (once the mapping exists, filtering may allow it).
	if peer.PublicAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.PublicAddr, Kind: "public", Order: order})
		order++
	}

	// Predicted symmetric mapping ports.
	//
	// Two independent dimensions are measured by STUN:
	//   PortStep  -- how much the NAT increments the external port per new
	//                local binding (measured by MeasurePortStep). This is the
	//                dimension exploited by the socket-pool spray.
	//   PortDelta -- how much the external port changes per destination.
	//                This only varies across destinations for symmetric NATs
	//                that are NOT increment-type; the old single-socket sweep
	//                around PortDelta is the fallback for that case.
	//
	// When both sides can spray (PortStep > 0 and PredictionSockets > 1) the
	// spray is aligned: socket k targets port_0 + k*peer_step.
	if peer.PublicAddr != nil {
		// "hard" = must use plant+spray. Symmetric and unmeasurable are obvious;
		// unknown/blocked are included deliberately: when we could not classify
		// the peer (STUN partly failed, or a network we have not seen), fail
		// safe into the aggressive traversal -- plant+spray is a superset that
		// still connects a cone-class peer via the plain public target, so an
		// ambiguous result must not silently skip the spray that NAT4 needs.
		hardPeer := isHardNAT(peer.Type)
		hardMy := isHardNAT(my.Type)
		if cfg.PredictionSockets > 1 && peer.PortStep > 0 && !hardPeer && !hardMy {
			// Both sides cone-class but the peer reports a per-binding step:
			// the step-aligned diagonal is the cheap aligned spray. A hard
			// (symmetric/unmeasurable) peer does NOT take this branch -- it
			// falls through to the plant+spray handling below, which also adds
			// the diagonal as an extra bet when a step is known.
			base := peer.PublicAddr.Port
			for k := 0; k < cfg.PredictionSockets; k++ {
				port := base + k*peer.PortStep
				if port < 1 || port > 65535 {
					continue
				}
				addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: port}
				eps = append(eps, Endpoint{Addr: addr, Kind: "predicted", Order: order, Socket: k})
				order++
			}
		} else if hardPeer || hardMy {
			// Hard-symmetric handling. A cellular CGNAT neither preserves the
			// local source port nor reports a PortStep, so the n4 block bet
			// alone misses every peer mapping. The two complementary roles are
			// what actually connect it (EasyTier's "hard-sym" birthday attack).
			// This runs regardless of the socket-pool size: the multi-IP spray
			// (the leg that cracks a destination-rotating CGNAT) uses only the
			// primary socket, so disabling the pool must NOT disable it.
			//
			//   hard side (this host, when hardMy): PLANT. Aim every pool
			//     socket at the peer's advertised public address so the NAT
			//     opens one mapping per socket -- each on a different random
			//     public port -- all pointed at the peer. The peer's blind
			//     spray then has something to hit.
			//
			//   easy side (peer is the hard one, we are cone): SPRAY. Fire a
			//     wide, freshly randomized port set at EVERY candidate public IP
			//     (primary + observation points) from the primary socket, whose
			//     public port is the one the hard side planted toward, so the
			//     spray collides with one of the peer's random mapping ports.
			//
			//   the block offset (n4) and the step diagonal are cheap extra bets
			//     for NATs that roughly preserve ports / report a step; they are
			//     never a replacement for the spray.
			if cfg.PredictionSockets > 1 && peer.PortStep > 0 {
				for k := 0; k < cfg.PredictionSockets; k++ {
					port := peer.PublicAddr.Port + k*peer.PortStep
					if port < 1 || port > 65535 {
						continue
					}
					addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: port}
					eps = append(eps, Endpoint{Addr: addr, Kind: "predicted", Order: order, Socket: k})
					order++
				}
			}
			if hardMy && cfg.PredictionSockets > 1 {
				for k := 1; k < cfg.PredictionSockets; k++ {
					eps = append(eps, Endpoint{Addr: peer.PublicAddr, Kind: "plant", Order: order, Socket: k})
					order++
				}
			}
			if cfg.PredictionSockets > 1 {
				offset := cfg.PeerPortOffset
				if offset == 0 {
					offset = defaultPeerPortOffset
				}
				port := peer.PublicAddr.Port + offset
				if port >= 1 && port <= 65535 {
					addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: port}
					for k := 0; k < cfg.PredictionSockets; k++ {
						eps = append(eps, Endpoint{Addr: addr, Kind: "block", Order: order, Socket: k})
						order++
					}
				}
			}
			if hardPeer {
				n := cfg.SymmetricSpray
				if n <= 0 {
					n = defaultSymmetricSpray
				}
				// Spray the full window at EVERY candidate IP: the primary the
				// server knows plus any observation-point addresses, because a
				// destination-rotating CGNAT may answer on any of them.
				ports := distinctPorts(n)
				for _, ip := range peer.CandidateIPs() {
					for _, sp := range ports {
						addr := &net.UDPAddr{IP: ip, Port: sp}
						eps = append(eps, Endpoint{Addr: addr, Kind: "spray", Order: order, Socket: 0})
						order++
					}
				}
			}
		}
	}

	// Relay: always reachable if the relay is up; keep as last resort.
	if cfg.RelayFallback && peer.RelayAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.RelayAddr, Kind: "relay", Order: order})
		order++
	}
	return eps
}

func sameLAN(a, b net.IP) bool {
	return len(a) == 4 && len(b) == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
}

// isHardNAT reports whether a NAT type must use the plant+spray traversal.
// symmetric/unmeasurable are definitive; unknown/blocked are included so an
// unclassified network fails safe into the aggressive path rather than into the
// cone fast path that silently drops the spray a symmetric NAT requires.
func isHardNAT(t stun.NATType) bool {
	switch t {
	case stun.NatSymmetric, stun.NatUnmeasurable, stun.NatUnknown, stun.NatBlocked:
		return true
	default:
		return false
	}
}

// distinctPorts returns n unique ports in the unprivileged UDP range, used for
// the easy-side spray at a hard peer. The global math/rand source is locked, so
// concurrent probe loops may call this. n is capped at the range size.
func distinctPorts(n int) []int {
	const low, high = 1024, 65535
	span := high - low + 1
	if n <= 0 {
		return nil
	}
	if n > span {
		n = span
	}
	seen := make(map[int]struct{}, n)
	out := make([]int, 0, n)
	for len(out) < n {
		p := low + rand.Intn(span)
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
