package punch

import (
	"encoding/binary"
	"math/rand"
	"net"

	"p2p/core/stun"
)

// defaultPeerPortOffset mirrors n4's "-o 20" fallback when a NAT preserves
// consecutive local ports into the external port space.
const defaultPeerPortOffset = 20

// defaultSymmetricSpray is how many distinct ports per round the cone side
// draws without replacement toward a hard (NAT4) peer.
const defaultSymmetricSpray = 512

const coldSprayFloor = 128

// defaultSprayIPMax caps how many distinct public IPs are sprayed per round
// when a hard peer announces a CGNAT egress PoolCIDR.
const defaultSprayIPMax = 64

// routeTier ranks candidate paths in strict ICE preference order so higher-tier
// routes (LAN > IPv6 > UPnP > Public) always upgrade lower-tier ones
// and can never be downgraded by delayed lower-tier packets.
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

func endpointTier(kind string) routeTier {
	switch kind {
	case "lan":
		return tierLAN
	case "ipv6":
		return tierIPv6
	case "upnp":
		return tierUPnP
	default:
		return tierPublic
	}
}

func maxPlannedTier(eps []Endpoint) routeTier {
	best := tierNone
	for _, ep := range eps {
		if t := endpointTier(ep.Kind); t > best {
			best = t
		}
	}
	if best == tierNone {
		return tierPublic
	}
	return best
}

func filterHigherTierEndpoints(eps []Endpoint, cur routeTier) []Endpoint {
	var out []Endpoint
	for _, ep := range eps {
		if endpointTier(ep.Kind) > cur {
			out = append(out, ep)
		}
	}
	return out
}

// classifyPacketTier determines the ICE route tier of an inbound packet from
// (ua, sockIdx) relative to local/remote NATInfo and config.
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

// Endpoint is one address the punch engine will probe.
type Endpoint struct {
	Addr   *net.UDPAddr
	Kind   string // "lan","upnp","ipv6","public","observed","preserve","predicted","pba","block","plant","spray"
	Order  int
	Socket int // index into Punch.Conns; 0 = primary, -1 = IPv6Conn
}

// NATInfo describes one side's reachability and NAT allocator behaviour.
type NATInfo struct {
	Type               stun.NATType
	PublicAddr         *net.UDPAddr
	PrivateAddr        *net.UDPAddr
	ExtraPrivateAddrs  []*net.UDPAddr
	PrivateCIDRs       []*net.IPNet
	PortDelta          int
	PortStep           int
	PortPreserve       bool
	PortPreserveOffset int
	PortBlockMin       int
	PortBlockMax       int
	ObservedMappings   []*net.UDPAddr
	PoolSize           int
	PoolPorts          []int
	IPv6Addr           *net.UDPAddr
	UPnPAddr           *net.UDPAddr
	// PublicIPs are additional distinct public addresses this peer was seen at
	// across multiple STUN observation points (a destination-rotating CGNAT).
	PublicIPs []net.IP
	// PoolCIDR is the inferred CGNAT egress prefix covering the peer's sampled
	// public IPs so the cone peer can spray the un-sampled egress IPs too.
	PoolCIDR *net.IPNet
}

// CandidateIPs returns every deduplicated public IPv4 address the peer might
// egress from: PublicAddr.IP first, then ObservedMappings IPs, then PublicIPs.
func (n NATInfo) CandidateIPs() []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			return // IPv6 is probed separately via IPv6Addr
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
	for _, m := range n.ObservedMappings {
		if m != nil {
			add(m.IP)
		}
	}
	for _, ip := range n.PublicIPs {
		add(ip)
	}
	return out
}

// adjacentCGNATIPs returns nearby IPs in the same /29 subnet when a CGNAT
// rotates egress IPs inside a small carrier block and only one IP was seen.
func adjacentCGNATIPs(primary net.IP, already []net.IP) []net.IP {
	ip4 := primary.To4()
	if ip4 == nil {
		return nil
	}
	seen := make(map[string]bool, len(already))
	for _, ip := range already {
		if v := ip.To4(); v != nil {
			seen[v.String()] = true
		}
	}
	base := binary.BigEndian.Uint32(ip4)
	netBase := base &^ uint32(7) // /29 block
	var out []net.IP
	for i := uint32(0); i < 8; i++ {
		cand := make(net.IP, 4)
		binary.BigEndian.PutUint32(cand, netBase|i)
		if !seen[cand.String()] && cand[3] != 0 && cand[3] != 255 {
			seen[cand.String()] = true
			out = append(out, cand)
		}
	}
	return out
}

// SprayIPs returns the candidate public IPs to spray in the given round: all
// sampled CandidateIPs first, followed by hosts in PoolCIDR up to max (or
// defaultSprayIPMax). When the covering pool is larger than max, consecutive
// rounds rotate their window offset so the whole pool is covered cleanly.
func (n NATInfo) SprayIPs(max, round int) []net.IP {
	out := n.CandidateIPs()
	if n.PoolCIDR == nil {
		return out
	}
	if max <= 0 {
		max = defaultSprayIPMax
	}
	base := n.PoolCIDR.IP.To4()
	ones, bits := n.PoolCIDR.Mask.Size()
	if base == nil || bits != 32 || ones < 20 {
		return out
	}
	seen := make(map[string]bool, len(out)+max)
	for _, ip := range out {
		seen[ip.String()] = true
	}
	total := 1 << (32 - ones)
	limit := total
	offset := 0
	if limit > max {
		limit = max
		if round > 0 {
			offset = (round * max) % total
		}
	}
	block := binary.BigEndian.Uint32(base)
	for i := 0; i < limit; i++ {
		idx := uint32((offset + i) % total)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, block+idx)
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	return out
}

// isHardNAT reports whether a peer's NAT behaves as NAT4 or unclassified
// (symmetric, unmeasurable, unknown, blocked, or multi-IP destination-rotating
// CGNAT) so ambiguous NATs fail safe into plant+spray rather than dropping
// straight to a cone-only single-target probe.
func (n NATInfo) isHardNAT() bool {
	if n.PoolCIDR != nil || len(n.CandidateIPs()) > 1 {
		return true
	}
	switch n.Type {
	case stun.NatSymmetric, stun.NatUnmeasurable, stun.NatUnknown, stun.NatBlocked:
		return true
	default:
		return false
	}
}

// Config tunes the punch engine.
type Config struct {
	PortPrediction    bool
	EnableLAN         bool
	PredictionRange   int
	ProbeIntervalMs   int
	PunchTimeoutMs    int
	PredictionSockets int
	PeerPortOffset    int
	SymmetricSpray    int
	// SprayIPMax caps distinct public IPs sprayed per round when PoolCIDR is set (default 64).
	SprayIPMax int
	// PunchPPS caps outbound spray/probe packets per second (default 1500)
	// so bursts do not overflow OS socket buffers or trigger CGNAT PPS policers.
	PunchPPS int
	// EscalateAfterMs is how long a cone-classified peer may fail to connect
	// before re-planning both sides as hard plant+spray (default 3000ms).
	EscalateAfterMs int
	OnLog           func(format string, args ...interface{})
}

// portDeck holds a Fisher-Yates shuffled permutation of all unprivileged UDP
// ports [1024..65535] so consecutive birthday-attack spray rounds sample
// WITHOUT replacement and never repeat ports until the full space is covered.
type portDeck struct {
	ports []int
	idx   int
}

func newPortDeck(skip map[int]bool) *portDeck {
	const low, high = 1024, 65535
	ports := make([]int, 0, high-low+1)
	for p := low; p <= high; p++ {
		if skip != nil && skip[p] {
			continue
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		for p := low; p <= high; p++ {
			ports = append(ports, p)
		}
	}
	shuffleInts(ports)
	return &portDeck{ports: ports}
}

func (d *portDeck) next(n int) []int {
	if n <= 0 || len(d.ports) == 0 {
		return nil
	}
	if n > len(d.ports) {
		n = len(d.ports)
	}
	out := make([]int, 0, n)
	for len(out) < n {
		if d.idx >= len(d.ports) {
			shuffleInts(d.ports)
			d.idx = 0
		}
		take := n - len(out)
		rem := len(d.ports) - d.idx
		if take > rem {
			take = rem
		}
		out = append(out, d.ports[d.idx:d.idx+take]...)
		d.idx += take
	}
	return out
}

func shuffleInts(a []int) {
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
}

func planTargets(my NATInfo, peer NATInfo, cfg Config) []Endpoint {
	return planTargetsWithDeck(my, peer, cfg, nil, 0)
}

// planTargetsWithDeck builds the ordered probing plan for NAT3<->NAT4 and all
// other NAT combinations without mutual exclusion bugs and keeping all easy-side
// probes on Socket 0 so NAT4's planted mappings accept inbound packets.
func planTargetsWithDeck(my NATInfo, peer NATInfo, cfg Config, deck *portDeck, round int) []Endpoint {
	var eps []Endpoint
	order := 0
	probed := make(map[string]bool)

	addEp := func(addr *net.UDPAddr, kind string, sock int) {
		if addr == nil || addr.Port < 1 || addr.Port > 65535 {
			return
		}
		// Keep Socket 0 deduped cleanly across deterministic legs; planted
		// pool sockets (sock > 0) share the target address, and spray already
		// pairs distinct ports with deduplicated IPs.
		if sock <= 0 && kind != "plant" && kind != "spray" {
			ak := "sock0|" + addr.String()
			if probed[ak] {
				return
			}
			probed[ak] = true
		}
		eps = append(eps, Endpoint{Addr: addr, Kind: kind, Order: order, Socket: sock})
		order++
	}

	// 1. Multi-interface / subnet-aware LAN shortcut.
	if cfg.EnableLAN {
		myPrivs := my.allPrivateAddrs()
		peerPrivs := peer.allPrivateAddrs()
		for _, pa := range peerPrivs {
			for _, ma := range myPrivs {
				if sameLAN(ma.IP, pa.IP, my.PrivateCIDRs, peer.PrivateCIDRs) {
					addEp(pa, "lan", 0)
					break
				}
			}
		}
	}

	// 2. IPv6 direct path (dual-stack bypasses IPv4 CGNAT when available).
	if peer.IPv6Addr != nil && my.IPv6Addr != nil {
		addEp(peer.IPv6Addr, "ipv6", -1)
	}

	// 3. Explicit UPnP / NAT-PMP / PCP external port mapping.
	if peer.UPnPAddr != nil {
		addEp(peer.UPnPAddr, "upnp", 0)
	}

	// 4. Primary public address.
	if peer.PublicAddr != nil {
		addEp(peer.PublicAddr, "public", 0)
	}

	// 5. Additional observed mappings from multi-STUN probing (exact IP:Port).
	for _, om := range peer.ObservedMappings {
		if om != nil {
			addEp(om, "observed", 0)
		}
	}

	if peer.PublicAddr != nil {
		hardPeer := peer.isHardNAT()
		hardMy := my.isHardNAT()
		easyMy := !hardMy
		candIPs := peer.CandidateIPs()

		// Spray targets: expand announced CGNAT PoolCIDR if present; otherwise on
		// later rounds (> 25) against a single-IP hard peer, also sample adjacent
		// /29 CGNAT egress IPs in case egress rotated silently.
		sprayIPs := peer.SprayIPs(cfg.SprayIPMax, round)
		if hardPeer && peer.PoolCIDR == nil && round > 25 && len(candIPs) == 1 {
			if adj := adjacentCGNATIPs(candIPs[0], candIPs); len(adj) > 0 && round%3 == 0 {
				sprayIPs = append(append([]net.IP(nil), candIPs...), adj...)
			}
		}

		// HARD LOCAL SIDE (NAT4): open mappings from every pool socket toward
		// the peer's reachable address(es) so its spray/probes can land on them.
		// On the first two rounds, plant sockets 1..127 first then 128..N so even
		// CGNATs with strict per-user port quotas map the primary window cleanly;
		// from round 2 onward, refresh a rotating staggered batch so NAT UDP
		// bindings stay warm at ~100-200 PPS without flooding NAT3 conntrack.
		if hardMy && cfg.PredictionSockets > 1 {
			plantSock := func(k int) {
				target := peer.PublicAddr
				if len(candIPs) > 1 {
					target = &net.UDPAddr{IP: candIPs[k%len(candIPs)], Port: peer.PublicAddr.Port}
				}
				addEp(target, "plant", k)
			}
			totalExtra := cfg.PredictionSockets - 1
			if round < 2 || totalExtra <= 16 {
				for k := 1; k < cfg.PredictionSockets; k++ {
					plantSock(k)
				}
			} else {
				batch := totalExtra / 16
				if batch < 8 {
					batch = 8
				}
				if batch > 32 {
					batch = 32
				}
				startIdx := ((round - 2) * batch) % totalExtra
				for i := 0; i < batch; i++ {
					k := 1 + (startIdx+i)%totalExtra
					plantSock(k)
				}
			}
			if peer.UPnPAddr != nil && round < 2 {
				for k := 1; k < cfg.PredictionSockets && k <= 16; k++ {
					addEp(peer.UPnPAddr, "plant", k)
				}
			}
		}

		// DETERMINISTIC + BIRTHDAY LEGS FOR HARD PEER (NAT4):
		// CRITICAL: When this host is the EASY side (NAT3), ALL probes MUST use
		// Socket 0 (whose public port the NAT4 peer knows and planted toward).
		// Using Socket 1..N on NAT3 causes NAT4 to drop 100% of those probes!
		// Even when both sides are hard (NAT4<->NAT4), Socket 0 carries the
		// advertised primary mapping, so Socket 0 is still the primary probe socket.
		probeSocket := 0
		_ = easyMy

		if hardPeer || peer.PortStep != 0 || peer.PortPreserve {
			// A. Port-preserving NAT4: mapped_port ≈ local_port + offset.
			if peer.PortPreserve {
				if len(peer.PoolPorts) > 0 {
					for _, lp := range peer.PoolPorts {
						p := lp + peer.PortPreserveOffset
						for _, ip := range candIPs {
							addEp(&net.UDPAddr{IP: ip, Port: p}, "preserve", probeSocket)
						}
					}
				} else if peer.PrivateAddr != nil {
					count := peer.PoolSize
					if count <= 0 {
						count = cfg.PredictionSockets
					}
					if count <= 0 {
						count = 64
					}
					for k := 0; k < count; k++ {
						p := peer.PrivateAddr.Port + peer.PortPreserveOffset + k
						for _, ip := range candIPs {
							addEp(&net.UDPAddr{IP: ip, Port: p}, "preserve", probeSocket)
						}
					}
				}
			}

			// B. Linear stepping NAT4: public_port[k] ≈ base + k * PortStep (with ±1 jitter).
			if peer.PortStep != 0 {
				steps := peer.PoolSize
				if cfg.PredictionSockets > steps {
					steps = cfg.PredictionSockets
				}
				if steps <= 0 {
					steps = 64
				}
				if steps > 256 {
					steps = 256
				}
				base := peer.PublicAddr.Port
				for k := 0; k < steps; k++ {
					center := base + k*peer.PortStep
					for _, jitter := range []int{0, -1, 1} {
						if k > 64 && jitter != 0 {
							continue // compensate Detect()+background drift up to 64 steps, exact step further out
						}
						p := center + jitter
						for _, ip := range candIPs {
							addEp(&net.UDPAddr{IP: ip, Port: p}, "predicted", probeSocket)
						}
					}
				}
			}

			// C. Port Block Allocation (PBA) NAT4: snap to power-of-2 BRAS block
			// alignment (64..1024) merged with observed sample margin and probe a
			// dense phase-rotated slice each round.
			if peer.PortBlockMax > peer.PortBlockMin && peer.PortBlockMax-peer.PortBlockMin <= 2048 {
				lo, hi := alignPBABounds(peer.PortBlockMin, peer.PortBlockMax)
				span := hi - lo + 1
				stride := 1
				if span > 384 {
					stride = span / 256
					if stride < 1 {
						stride = 1
					}
				}
				phase := round % stride
				for p := lo + phase; p <= hi; p += stride {
					for _, ip := range candIPs {
						addEp(&net.UDPAddr{IP: ip, Port: p}, "pba", probeSocket)
					}
				}
			}

			// D. Block offset bet: peer.PublicAddr.Port + offset + [0..window] on Socket 0.
			if cfg.PredictionSockets > 1 && hardPeer {
				offset := cfg.PeerPortOffset
				if offset == 0 {
					offset = defaultPeerPortOffset
				}
				win := 16
				if peer.PoolSize > 0 && peer.PoolSize < win {
					win = peer.PoolSize
				}
				base := peer.PublicAddr.Port + offset
				for j := 0; j < win; j++ {
					for _, ip := range candIPs {
						addEp(&net.UDPAddr{IP: ip, Port: base + j}, "block", probeSocket)
					}
				}
			}

			// E. Legacy single-socket PortDelta sweep when delta != 0.
			if cfg.PortPrediction && peer.PortDelta != 0 && peer.PortStep == 0 {
				span := cfg.PredictionRange
				if span <= 0 {
					span = 6
				}
				base := peer.PublicAddr.Port
				for k := -span; k <= span*2; k++ {
					for _, ip := range candIPs {
						addEp(&net.UDPAddr{IP: ip, Port: base + k*peer.PortDelta}, "predicted", probeSocket)
					}
				}
			}

			// F. Weighted birthday-attack spray WITHOUT replacement via portDeck on Socket 0.
			// Prioritise STUN-observed CandidateIPs with the full batch of fresh ports
			// (interleaved across confirmed IPs so rounds stay fast), and spread a
			// bounded per-IP slice over any un-sampled PoolCIDR / adjacent IPs so
			// wide /26../24 pools do not dilute active IPs 64x or flood NAT3 conntrack.
			if hardPeer {
				n := cfg.SymmetricSpray
				if n < 0 {
					n = 0
				} else if n == 0 {
					n = defaultSymmetricSpray
				}
				if n > 0 {
					var ports []int
					if deck != nil {
						ports = deck.next(n)
					} else {
						ports = distinctPorts(n)
					}
					candSet := make(map[string]bool, len(candIPs))
					for _, ip := range candIPs {
						candSet[ip.String()] = true
					}
					var coldIPs []net.IP
					for _, ip := range sprayIPs {
						if !candSet[ip.String()] {
							coldIPs = append(coldIPs, ip)
						}
					}
					for _, sp := range ports {
						for _, ip := range candIPs {
							addEp(&net.UDPAddr{IP: ip, Port: sp}, "spray", probeSocket)
						}
					}
					if len(coldIPs) > 0 {
						coldCount := len(ports)
						if len(coldIPs) > 4 {
							// Keep hot CandidateIPs at full window FIRST, while giving
							// un-sampled cold pool IPs half the window (floored at
							// coldSprayFloor=128) so wide pools stay fast on common
							// networks without starving unsampled-egress rescue.
							coldCount = len(ports) / 2
							if coldCount < coldSprayFloor {
								coldCount = coldSprayFloor
							}
							if coldCount > len(ports) {
								coldCount = len(ports)
							}
						}
						for _, sp := range ports[:coldCount] {
							for _, ip := range coldIPs {
								addEp(&net.UDPAddr{IP: ip, Port: sp}, "spray", probeSocket)
							}
						}
					}
				}
			}
		}
	}
	return eps
}

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

// distinctPorts returns n unique ports in [1024..65535].
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

// alignPBABounds snaps an observed PBA port range [minP..maxP] to the smallest
// power-of-2 BRAS port block (256..1024, which encloses 64/128/256 blocks in a
// single 256-probe round) covering both endpoints, merged with [minP-32..maxP+128]
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
