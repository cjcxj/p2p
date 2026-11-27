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

// defaultSymmetricSpray is how many random ports the easy side fires at each
// hard peer public IP each round -- the EasyTier "hard-sym" birthday leg that
// works when the peer's NAT randomizes the per-socket public port.
const defaultSymmetricSpray = 1024

// defaultSprayIPMax bounds how many distinct public addresses the spray leg
// covers when a peer announces an egress pool. A CGNAT block is usually a few
// dozen contiguous addresses; the cap stops a mistakenly-wide prefix (e.g. /24)
// from multiplying the birthday attack into an unbounded flood.
const defaultSprayIPMax = 64

// coldSprayFloor is the minimum probe ports given to each un-observed pool IP
// in the weighted spray. Half the full window, but never below this, so a wide
// pool speeds up the observed IPs without starving the unsampled-egress rescue.
const coldSprayFloor = 128

// defaultPunchPPS is the probe rate ceiling. EasyTier-class hard-sym punching
// lands within seconds at a couple thousand packets/s; going far above that
// buys no coverage and instead starves the host NIC and overflows the router's
// NAT session table, which is what takes an entire network offline.
const defaultPunchPPS = 1500

// plantStaggerDiv: after the first two rounds, each round refreshes only 1 of
// every plantStaggerDiv plant/block sockets (rotating), so a large plant pool
// keeps its NAT mappings warm without re-flooding the CGNAT port quota.
const plantStaggerDiv = 8

// Endpoint is one address the punch engine will probe.
type Endpoint struct {
	Addr   *net.UDPAddr
	Kind   string // "lan","public","upnp","ipv6","predicted","block","plant","preserve","pba","spray"
	Order  int
	Socket int // index into Punch.Conns; 0 = primary
}

// NATInfo describes one side's reachability from the other side's
// perspective.
type NATInfo struct {
	Type        stun.NATType
	PublicAddr  *net.UDPAddr
	PrivateAddr *net.UDPAddr
	// ExtraPrivateAddrs are this host's other interface addresses (VPN adapter,
	// wired plus Wi-Fi, hotspot) on the same socket port. A peer that shares one
	// of them, but not the one we happened to report first, still gets a LAN path.
	ExtraPrivateAddrs []*net.UDPAddr
	PortDelta         int
	PortStep          int
	// PortPreserve says this peer's NAT keeps a constant offset between the local
	// source port and the mapped port, and PortPreserveOffset is that offset. When
	// it holds, every socket in the peer's pool lands on a port we can compute
	// rather than search, which is the difference between a few hundred aimed
	// probes and a blind spray.
	PortPreserve       bool
	PortPreserveOffset int
	// PortBlockMin/PortBlockMax bound the block this peer's allocator hands ports
	// from (port block allocation). Zero means not established. A narrow block
	// turns a blind 1..65535 search into a dense sweep of a few hundred ports.
	PortBlockMin int
	PortBlockMax int
	// IPv6Addr is a globally reachable IPv6 address the peer announced. When we are
	// dual-stack too, this is the best path available: no IPv4 NAT is involved.
	IPv6Addr *net.UDPAddr
	// PublicIPs are additional distinct public addresses this peer was seen at
	// across multiple STUN observation points (a destination-rotating CGNAT).
	// Empty for ordinary NATs; the spray leg aims at all of them plus
	// PublicAddr.IP.
	PublicIPs []net.IP
	// PoolCIDR is the address block the peer announced as its egress pool. A
	// carrier CGNAT that re-dials within a contiguous block exposes only a few
	// of its IPs to STUN observation points, so the sampled PublicIPs can miss
	// the exact address used toward a given destination. When present the spray
	// leg covers the whole block (bounded by Config.SprayIPMax), which turns
	// "we happened to sample the right IP" into a deterministic hit.
	PoolCIDR *net.IPNet
	// UPnPAddr is an address this peer pinned on its own gateway (NAT-PMP or
	// UPnP IGD). It is a deterministic target that needs no port guess to
	// collide with, so it is probed alongside the punched candidates whenever
	// the peer managed to get one.
	UPnPAddr *net.UDPAddr
	// PrivateCIDRs are the subnets this host's own interfaces sit on, as
	// announced by the peer (or measured locally for our own side). They make
	// the same-LAN shortcut exact on non-/24 links instead of guessing the mask
	// from the third octet.
	PrivateCIDRs []*net.IPNet
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

// SprayIPs returns the addresses the easy-side spray leg must cover: every
// sampled candidate first (cheap, likely), then the whole announced egress
// pool so a destination-rotating CGNAT cannot hide behind the one IP it uses
// toward us. Expansion is capped at max hosts (<=0 uses defaultSprayIPMax) so a
// peer that reports a /24 pool cannot make the spray explode.
// SprayIPs returns the addresses the spray leg should aim at. round selects
// which slice of an announced pool larger than the per-round budget is covered:
// a fixed window only ever hits the same addresses, so a peer whose egress sits
// outside it stays unreachable no matter how many rounds run. Rotating the
// window by one budget per round covers the whole block in total/budget rounds.
// Observed addresses always come first and are never displaced by rotation.
// safety margin inside [1024..65535].
func alignPBABounds(minP, maxP int) (int, int) {
	lo := minP - 32
	hi := maxP + 128
	for _, blockSize := range []int{256, 512, 1024} {
		bLo := (minP / blockSize) * blockSize
		bHi := bLo + blockSize - 1
		if maxP <= bHi {
			if bLo < lo {
				lo = bLo
			}
			if bHi > hi {
				hi = bHi
			}
			break
		}
	}
	if lo < 1024 {
		lo = 1024
	}
	if hi > 65535 {
		hi = 65535
	}
	return lo, hi
}

func (n NATInfo) SprayIPs(max, round int) []net.IP {
	out := n.CandidateIPs()
	if n.PoolCIDR == nil {
		return out
	}
	if max <= 0 {
		max = defaultSprayIPMax
	}
	seen := make(map[string]bool, len(out))
	for _, ip := range out {
		seen[ip.String()] = true
	}
	base := n.PoolCIDR.IP.To4()
	ones, bits := n.PoolCIDR.Mask.Size()
	if base == nil || bits != 32 {
		return out
	}
	total := 1 << (32 - ones)
	if ones < 20 {
		// A block wider than /20 is not a carrier egress pool, and spraying it
		// would spend the whole budget on addresses nobody ever assigns. Fall
		// back to the sampled set, which is at least known-real. The announcing
		// side refuses to emit such a prefix; this is the matching guard.
		return out
	}
	limit := total
	if limit > max {
		limit = max
	}
	// Start from the sampled base address and walk forward, so the addresses we
	// were most likely to observe are sprayed first. The window is aligned to its
	// own size, which is the shape a CGNAT hands out contiguous blocks in.
	start := ipToU32(base)
	poolBase := start & ^uint32(total-1)
	block := start & ^uint32(limit-1)
	if total > limit && round > 0 {
		// Round 0 keeps the sampled address inside its own aligned window, which is
		// where a carrier most recently handed us a mapping. Later rounds walk the
		// pool from its base one window at a time, so the whole block is reached
		// within total/limit + 1 rounds instead of re-spraying one slice forever.
		block = poolBase + uint32(round-1)%uint32(total/limit)*uint32(limit)
	}
	for i := 0; i < limit; i++ {
		ip := u32ToIP(block + uint32(i))
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

func ipToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func u32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Config tunes the punch engine.
type Config struct {
	// PortPrediction enables port-range probing for symmetric NATs.
	PortPrediction bool
	// EnableLAN allows probing the private address for same-LAN peers.
	EnableLAN bool
	// PredictionRange is the number of ports probed on each side of the
	// predicted symmetric mapping (default 4).
	PredictionRange int
	// ProbeInterval is the delay between probe bursts (default 200ms).
	ProbeIntervalMs int
	// PunchTimeout is how long to punch before giving up on this peer.
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
	// SprayIPMax bounds how many distinct public addresses the spray leg covers
	// when a hard peer announces an egress pool. 0 = defaultSprayIPMax (64).
	SprayIPMax int
	// PunchPPS caps how many probe packets the engine sends per second per peer.
	// Without it a wide CGNAT spray (pool IPs x port window) blasts the host NIC
	// and, worse, exhausts the home router's NAT conntrack table, which takes
	// the whole network down -- not just this app. 0 = defaultPunchPPS.
	PunchPPS int
	// EscalateAfterMs is how long a cone-classified peer may fail to connect
	// before the engine re-plans it as hard (plant+spray). Guards against a
	// symmetric CGNAT being flakily classified as cone, which otherwise strands
	// the link on a single public probe that never re-rolls. 0 = 3000ms.
	EscalateAfterMs int
	// OnLog, when set, receives verbose hole-punching flow messages.
	OnLog func(format string, args ...interface{})
}

// planTargets builds the ordered list of endpoints to probe for the remote
// peer, encoding the NAT combination strategy matrix. The same matrix is
// applied symmetrically by both sides (simultaneous probing).
func planTargets(my NATInfo, peer NATInfo, cfg Config, round int) []Endpoint {
	var eps []Endpoint
	order := 0

	// LAN shortcut: any peer private address that shares any of our links. The
	// single-address comparison before it missed a host whose second interface
	// (wired plus Wi-Fi, VPN, hotspot) was the one on the peer's subnet.
	if cfg.EnableLAN {
		peerPrivs := peer.allPrivateAddrs()
		myPrivs := my.allPrivateAddrs()
		seenLAN := map[string]bool{}
		for _, pa := range peerPrivs {
			if pa == nil || pa.IP == nil || seenLAN[pa.String()] {
				continue
			}
			for _, ma := range myPrivs {
				if ma != nil && sameLAN(ma.IP, pa.IP, my.PrivateCIDRs, peer.PrivateCIDRs) {
					seenLAN[pa.String()] = true
					eps = append(eps, Endpoint{Addr: pa, Kind: "lan", Order: order})
					order++
					break
				}
			}
		}
	}

	// Direct IPv6: both sides globally reachable on v6 means the IPv4 CGNAT is
	// irrelevant. Sent on the dual-stack socket (-1), since the IPv4 pool cannot
	// carry it.
	if peer.IPv6Addr != nil && my.IPv6Addr != nil {
		eps = append(eps, Endpoint{Addr: peer.IPv6Addr, Kind: "ipv6", Order: order, Socket: -1})
		order++
	}

	// Public address: always probed. Works for every cone combination and
	// often for symmetric (once the mapping exists, filtering may allow it).
	if peer.PublicAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.PublicAddr, Kind: "public", Order: order})
		order++
	}

	// A gateway-mapped address is the one peer-side target that needs no guess:
	// the peer's router forwards it to the peer before the peer has sent us
	// anything, so it is aimed at directly, ahead of the port bets.
	if peer.UPnPAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.UPnPAddr, Kind: "upnp", Order: order, Socket: 0})
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
				eps = append(eps, Endpoint{Addr: addr, Kind: "predicted", Order: order, Socket: 0})
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
					eps = append(eps, Endpoint{Addr: addr, Kind: "predicted", Order: order, Socket: 0})
					order++
				}
			}
			// A measured port-preserving offset is the strongest bet available:
			// the peer's pool socket k maps to privatePort+offset+k, so the whole
			// pool is addressable by arithmetic instead of search. It is used only
			// when STUN actually measured the property -- inventing an offset would
			// spend the round budget on ports the peer is certainly not on.
			//
			// Assumption: the peer's pool sockets bind contiguously upward from the
			// private port it announced. Our own clients do (sdk binds
			// StepProbePort+i), so this needs no extra wire field; a third-party
			// peer whose pool is scattered would need it to announce the ports
			// themselves.
			if peer.PortPreserve && peer.PrivateAddr != nil && peer.PublicAddr != nil {
				count := cfg.PredictionSockets
				if count <= 0 {
					count = 64
				}
				for k := 0; k < count; k++ {
					port := peer.PrivateAddr.Port + peer.PortPreserveOffset + k
					if port < 1 || port > 65535 {
						continue
					}
					addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: port}
					eps = append(eps, Endpoint{Addr: addr, Kind: "preserve", Order: order, Socket: 0})
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
					// The probes stay on socket 0 because that is the external the
					// peer's plant mapping aimed at. But firing the SAME guess once per
					// socket repeated one destination PredictionSockets times -- the
					// first packet told us everything the rest did. Walk consecutive
					// ports from the offset guess instead, so the same budget covers a
					// window and the verbose log stops carrying N identical targets.
					for k := 0; k < cfg.PredictionSockets; k++ {
						p := port + k
						if p < 1 || p > 65535 {
							continue
						}
						addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: p}
						eps = append(eps, Endpoint{Addr: addr, Kind: "block", Order: order, Socket: 0})
						order++
					}
				}
			}
			// Port block allocation: when the allocator was measured to hand ports
			// from a narrow block, sweep that block densely. The phase rotates per
			// round so a stride-thinned sweep still covers everything within
			// stride rounds, while each round stays inside the packet budget.
			if peer.PublicAddr != nil && peer.PortBlockMax > peer.PortBlockMin &&
				peer.PortBlockMax-peer.PortBlockMin <= 2048 {
				lo, hi := alignPBABounds(peer.PortBlockMin, peer.PortBlockMax)
				if lo < 1 {
					lo = 1
				}
				if hi > 65535 {
					hi = 65535
				}
				span := hi - lo + 1
				stride := 1
				if span > 384 {
					stride = span / 256
					if stride < 1 {
						stride = 1
					}
				}
				for p := lo + round%stride; p <= hi; p += stride {
					addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: p}
					eps = append(eps, Endpoint{Addr: addr, Kind: "pba", Order: order, Socket: 0})
					order++
				}
			}
			if hardPeer {
				n := cfg.SymmetricSpray
				if n <= 0 {
					n = defaultSymmetricSpray
				}
				// Weighted anti-dilution spray. The announced pool can hold many
				// addresses STUN never observed (a /28 has 16, only 2-3 sampled).
				// Equal-window spray spends ~90% of the budget on cold IPs -- the
				// 51s convergence we measured live. So OBSERVED egress IPs get the
				// full window (interleaved, fast common case), while cold pool IPs
				// keep max(half-window, coldSprayFloor) ports each -- enough to
				// still collide with the peer's planted mappings so the rare
				// UNSAMPLED-egress rescue (Unicom .102) does not regress. This is
				// the formula the sibling build validated live (10/10, 2-4s).
				observed := peer.CandidateIPs()
				isObserved := make(map[string]bool, len(observed))
				for _, ip := range observed {
					isObserved[ip.String()] = true
				}
				var coldIPs []net.IP
				for _, ip := range peer.SprayIPs(cfg.SprayIPMax, round) {
					if !isObserved[ip.String()] {
						coldIPs = append(coldIPs, ip)
					}
				}
				hotPorts := distinctPorts(n)
				for _, sp := range hotPorts {
					for _, ip := range observed {
						addr := &net.UDPAddr{IP: ip, Port: sp}
						eps = append(eps, Endpoint{Addr: addr, Kind: "spray", Order: order, Socket: 0})
						order++
					}
				}
				if len(coldIPs) > 0 {
					coldN := len(hotPorts) / 2
					if coldN < coldSprayFloor {
						coldN = coldSprayFloor
					}
					if coldN > len(hotPorts) {
						coldN = len(hotPorts)
					}
					coldPorts := distinctPorts(coldN)
					for _, sp := range coldPorts {
						for _, ip := range coldIPs {
							addr := &net.UDPAddr{IP: ip, Port: sp}
							eps = append(eps, Endpoint{Addr: addr, Kind: "spray", Order: order, Socket: 0})
							order++
						}
					}
				}
			}
		}
	}

	// (No relay fallback: this is a pure-P2P engine. If direct punching fails,
	// the link simply does not connect -- there is no relay data path.)
	return eps
}

// routeTier ranks the kinds of direct path we can end up on, best first. Once a
// link is established on a better path it must not be dragged down by a later
// packet that happens to arrive on a worse one: a LAN session does not give way
// to the public mapping just because a public-socket probe still lands.
type routeTier int

const (
	tierNone   routeTier = 0
	tierPublic routeTier = 20
	tierUPnP   routeTier = 30
	tierIPv6   routeTier = 40
	tierLAN    routeTier = 50
)

func (t routeTier) String() string {
	switch t {
	case tierLAN:
		return "lan"
	case tierIPv6:
		return "ipv6"
	case tierUPnP:
		return "upnp"
	case tierPublic:
		return "public"
	default:
		return "none"
	}
}

// classifyPacketTier reports which path an inbound packet from ua arrived on.
// sockIdx -1 is the dual-stack socket, reserved for the IPv6 path.
func classifyPacketTier(my, peer NATInfo, cfg Config, ua *net.UDPAddr, sockIdx int) routeTier {
	if ua == nil {
		return tierNone
	}
	if sockIdx == -1 || (ua.IP != nil && ua.IP.To4() == nil) {
		return tierIPv6
	}
	if cfg.EnableLAN && ua.IP != nil && ua.IP.To4() != nil {
		myPrivs := my.allPrivateAddrs()
		peerPrivs := peer.allPrivateAddrs()
		for _, pa := range peerPrivs {
			if pa == nil || !pa.IP.Equal(ua.IP) || (pa.Port != 0 && pa.Port != ua.Port) {
				continue
			}
			for _, ma := range myPrivs {
				if ma != nil && sameLAN(ma.IP, pa.IP, my.PrivateCIDRs, peer.PrivateCIDRs) {
					return tierLAN
				}
			}
		}
	}
	if peer.UPnPAddr != nil && ua.IP != nil &&
		ua.IP.Equal(peer.UPnPAddr.IP) && ua.Port == peer.UPnPAddr.Port {
		return tierUPnP
	}
	return tierPublic
}

// allPrivateAddrs is the primary private address plus any the host announced from
// its other interfaces, with the duplicate primary filtered out.
func (n NATInfo) allPrivateAddrs() []*net.UDPAddr {
	var out []*net.UDPAddr
	if n.PrivateAddr != nil && n.PrivateAddr.IP != nil {
		out = append(out, n.PrivateAddr)
	}
	for _, a := range n.ExtraPrivateAddrs {
		if a != nil && a.IP != nil {
			out = append(out, a)
		}
	}
	return out
}

// sameLAN reports whether two private addresses share a link. The announced
// subnets decide when they exist -- that covers a /29 carrier link, a /21 office
// VLAN, and a host with several interfaces, none of which the coarse fallback
// reads correctly. Without announced subnets the old /24 comparison still
// applies, so a peer that predates the field loses nothing. The subnets are
// additive by design: an announcement that does not match must not take away a
// same-LAN path the coarse rule already gave two hosts on one /24.
func sameLAN(a, b net.IP, aCIDRs, bCIDRs []*net.IPNet) bool {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for _, n := range aCIDRs {
		if n != nil && n.Contains(a4) && n.Contains(b4) {
			return true
		}
	}
	for _, n := range bCIDRs {
		if n != nil && n.Contains(a4) && n.Contains(b4) {
			return true
		}
	}
	return a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
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
