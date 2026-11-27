package stun

import (
	"fmt"
	"net"
	"time"
)

// NATType classifies the behaviour of the network address translation in
// front of the client.
type NATType string

// NAT types.
const (
	NatOpen               NATType = "open"
	NatFullCone           NATType = "full_cone"
	NatRestrictedCone     NATType = "restricted_cone"
	NatPortRestrictedCone NATType = "port_restricted_cone"
	NatSymmetric          NATType = "symmetric"
	// NatCone means the NAT repeats one mapping for every destination (cone),
	// while the exact inbound filter level was not testable on a single-port STUN.
	NatCone NATType = "cone"
	// NatUnmeasurable means filtering was at least port-dependent, but no
	// alternate destination answered, so cone and symmetric were never told
	// apart. Treat it as potentially symmetric.
	NatUnmeasurable NATType = "unmeasurable"
	NatUnknown      NATType = "unknown"
	NatBlocked      NATType = "blocked"
)

// Detection holds the result of a NAT classification and rich allocation hints
// used to drive pure-P2P NAT3<->NAT4 hole punching.
type Detection struct {
	NATType NATType
	// MappedAddr is the public mapping observed for the primary STUN server.
	MappedAddr *net.UDPAddr
	// LocalAddr is the primary local address of the client socket.
	LocalAddr *net.UDPAddr
	// LocalAddrs lists all private/LAN IPv4 socket addresses on active host
	// interfaces so multi-homed/VPN/VMware/Wi-Fi peers can establish same-LAN paths.
	LocalAddrs []*net.UDPAddr
	// LocalCIDRs are the interface subnet strings (e.g. "192.168.10.5/24")
	// paired with LocalAddrs for accurate subnet matching.
	LocalCIDRs []string
	// PortDelta is the per-mapping port increment observed between primary and
	// alternate STUN destinations.
	PortDelta int
	// Secondary records which alternate destination produced the comparison.
	Secondary string
	// PortStep is how far this NAT's public port moves per new binding (0 = random).
	PortStep int
	// PortPreserve is true when the NAT allocates public ports at a fixed offset
	// from the client's local source port.
	PortPreserve bool
	// PortPreserveOffset is mapped_port - local_port when PortPreserve is true.
	PortPreserveOffset int
	// PortBlockMin and PortBlockMax bracket the NAT's Port Block Allocation (PBA)
	// range when consecutive or multi-STUN probes cluster within 2048 ports.
	PortBlockMin int
	PortBlockMax int
	// ObservedIPs is the deduplicated list of distinct public IPv4 addresses seen
	// across the primary and all responding STUN observation points.
	ObservedIPs []net.IP
	// ObservedMappings holds every distinct public ip:port seen across STUN
	// observation points (first is MappedAddr).
	ObservedMappings []*net.UDPAddr
	// IPv6Addr is the globally routable IPv6 UDP address when available.
	IPv6Addr *net.UDPAddr
	// UPnPAddr is an explicit router-mapped external UDP address via UPnP/NAT-PMP/PCP.
	UPnPAddr *net.UDPAddr
	// FilterMeasured reports whether the cone subtype was directly observed.
	FilterMeasured bool
	// Note carries diagnostic context about the NAT classification.
	Note string
}

// PublicAddr returns the mapped public address as a host:port string.
func (d *Detection) PublicAddr() string {
	if d.MappedAddr == nil {
		return ""
	}
	return d.MappedAddr.String()
}

// CoveringPool returns the smallest IPv4 prefix containing the primary mapped
// address and all STUN-observed egress IPv4 addresses. A destination-rotating
// CGNAT often rotates across a contiguous carrier block (e.g. /27 or /26) and
// only exposes a subset of those IPs to STUN probes. Returns nil when fewer
// than two distinct public IPv4s were seen or when they span wider than /20.
func (d *Detection) CoveringPool() *net.IPNet {
	if d == nil || d.MappedAddr == nil {
		return nil
	}
	var ips []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		ip4 := ip.To4()
		if ip4 == nil || seen[ip4.String()] {
			return
		}
		seen[ip4.String()] = true
		ips = append(ips, ip4)
	}
	add(d.MappedAddr.IP)
	for _, ip := range d.ObservedIPs {
		add(ip)
	}
	for _, m := range d.ObservedMappings {
		if m != nil {
			add(m.IP)
		}
	}
	if len(ips) < 2 {
		return nil
	}
	first := ipv4ToU32(ips[0])
	var diff uint32
	for _, ip := range ips[1:] {
		diff |= first ^ ipv4ToU32(ip)
	}
	ones := 32
	for ones > 0 && diff != 0 {
		diff >>= 1
		ones--
	}
	if ones < 20 {
		return nil
	}
	mask := net.CIDRMask(ones, 32)
	base := ips[0].Mask(mask)
	return &net.IPNet{IP: base, Mask: mask}
}

func ipv4ToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// Method explains what the classification rested on.
func (d *Detection) Method() string {
	var s string
	switch {
	case d.NATType == NatSymmetric:
		s = fmt.Sprintf("second destination %s gave a different mapping (delta %+d)", d.Secondary, d.PortDelta)
	case d.NATType == NatPortRestrictedCone:
		s = fmt.Sprintf("second destination %s repeated the mapping, change-port answer dropped", d.Secondary)
	case d.NATType == NatFullCone:
		s = "change-IP answer arrived: no address filtering"
	case d.NATType == NatRestrictedCone:
		s = "change-IP answer dropped: address-filtered but not port-filtered"
	case d.NATType == NatCone:
		s = fmt.Sprintf("second destination %s repeated the mapping", d.Secondary)
	case d.NATType == NatUnmeasurable:
		s = "no alternate destination answered"
	}
	if d.PortPreserve {
		s += fmt.Sprintf("; port-preserving (offset %+d)", d.PortPreserveOffset)
	}
	if d.PortStep != 0 {
		s += fmt.Sprintf("; port step %+d per new binding", d.PortStep)
	}
	if d.PortBlockMin > 0 && d.PortBlockMax >= d.PortBlockMin {
		s += fmt.Sprintf("; PBA block %d..%d", d.PortBlockMin, d.PortBlockMax)
	}
	if len(d.ObservedIPs) > 1 {
		s += fmt.Sprintf("; %d egress IPs", len(d.ObservedIPs))
	}
	if d.IPv6Addr != nil {
		s += fmt.Sprintf("; ipv6=%s", d.IPv6Addr)
	}
	if d.UPnPAddr != nil {
		s += fmt.Sprintf("; upnp=%s", d.UPnPAddr)
	}
	if d.Note != "" {
		s += "; " + d.Note
	}
	return s
}

// localIPFor returns the local IPv4 address the OS would use to reach server.
func localIPFor(server *net.UDPAddr) net.IP {
	if server == nil {
		return nil
	}
	c, err := net.DialUDP("udp", nil, server)
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP
	}
	return nil
}

// enumerateLocalAddrs returns all non-loopback IPv4 interface addresses paired
// with the socket port, plus their interface CIDR strings.
func enumerateLocalAddrs(port int, primary *net.UDPAddr) ([]*net.UDPAddr, []string) {
	if port <= 0 {
		return nil, nil
	}
	var addrs []*net.UDPAddr
	var cidrs []string
	seenIP := map[string]bool{}
	if primary != nil && primary.IP != nil && !primary.IP.IsUnspecified() {
		if ip4 := primary.IP.To4(); ip4 != nil {
			seenIP[ip4.String()] = true
			addrs = append(addrs, &net.UDPAddr{IP: ip4, Port: port})
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs, cidrs
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifAddrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			cidrs = append(cidrs, (&net.IPNet{IP: ip4, Mask: ipNet.Mask}).String())
			if !seenIP[ip4.String()] {
				seenIP[ip4.String()] = true
				addrs = append(addrs, &net.UDPAddr{IP: ip4, Port: port})
			}
		}
	}
	return addrs, cidrs
}

// Detect classifies the NAT over c.Conn, concurrently probing all configured
// STUN servers in ~1 RTT and measuring symmetric allocation patterns (step,
// port preservation, PBA port block) and rotating CGNAT egress IPs.
func (c *Client) Detect() (*Detection, error) {
	// Test I: plain binding to primary.
	t1, _, err := c.BindRequest(false, false)
	if err != nil {
		return nil, err
	}
	mapped1, err := t1.MappedAddress()
	if err != nil {
		return nil, fmt.Errorf("stun: %w", err)
	}
	local := c.Conn.LocalAddr()
	localUDP, _ := local.(*net.UDPAddr)
	if localUDP != nil && (localUDP.IP == nil || localUDP.IP.IsUnspecified()) {
		if ip := localIPFor(c.Server); ip != nil {
			localUDP = &net.UDPAddr{IP: ip, Port: localUDP.Port}
		}
	}
	localPort := 0
	if localUDP != nil {
		localPort = localUDP.Port
	}
	localAddrs, localCIDRs := enumerateLocalAddrs(localPort, localUDP)

	d := &Detection{
		NATType:    NatUnknown,
		MappedAddr: mapped1,
		LocalAddr:  localUDP,
		LocalAddrs: localAddrs,
		LocalCIDRs: localCIDRs,
	}
	if mapped1.IP != nil {
		d.ObservedIPs = []net.IP{mapped1.IP}
		d.ObservedMappings = []*net.UDPAddr{mapped1}
	}

	// Not behind a NAT: public mapping equals local socket address.
	if localUDP != nil && mapped1.IP.Equal(localUDP.IP) && mapped1.Port == localUDP.Port {
		d.NATType = NatOpen
		return d, nil
	}

	// Test III: ask the server to answer from port+1 with a single quick probe
	// so single-port deployments do not stall waiting on retries.
	t3Client := *c
	t3Client.Retries = 0
	if t3Client.Timeout <= 0 || t3Client.Timeout > 350*time.Millisecond {
		t3Client.Timeout = 350 * time.Millisecond
	}
	t3, _, _ := t3Client.BindRequest(false, true)
	if t3 != nil {
		t2Client := t3Client
		t2, _, _ := t2Client.BindRequest(true, false)
		if t2 != nil {
			d.NATType = NatFullCone
			d.FilterMeasured = true
		} else {
			d.NATType = NatCone
			d.Note = "not port-filtered; full vs address-restricted needs a second server address"
		}
		return d, nil
	}

	// Filtering is port-dependent (NAT3 or NAT4). Probe every alternate STUN
	// destination concurrently over the same socket AND launch ephemeral
	// multi-STUN egress discovery in parallel.
	altAddrs := c.secondaryAddrs()
	secTimeout := c.SecondaryTimeout
	if secTimeout <= 0 {
		secTimeout = 800 * time.Millisecond
	}

	obsCh := make(chan []*net.UDPAddr, 1)
	go func() {
		obsCh <- c.ObserveEgress(altAddrs, secTimeout, secTimeout+200*time.Millisecond)
	}()

	results := c.ConcurrentBindAll(altAddrs, secTimeout)

	altAnswered := false
	answered := false
	differs := false
	delta := 0
	firstSec := ""

	seenIP := map[string]bool{}
	seenMap := map[string]bool{}
	if mapped1.IP != nil {
		seenIP[mapped1.IP.String()] = true
		seenMap[mapped1.String()] = true
	}

	addObserved := func(m *net.UDPAddr) {
		if m == nil || m.IP == nil {
			return
		}
		if !seenIP[m.IP.String()] {
			seenIP[m.IP.String()] = true
			d.ObservedIPs = append(d.ObservedIPs, m.IP)
		}
		k := m.String()
		if !seenMap[k] {
			seenMap[k] = true
			d.ObservedMappings = append(d.ObservedMappings, m)
		}
	}

	for _, r := range results {
		answered = true
		fromServerAltPort := c.Server != nil && r.Server != nil && r.Server.IP != nil &&
			r.Server.IP.Equal(c.Server.IP) && r.Server.Port == c.Server.Port+1
		if fromServerAltPort {
			altAnswered = true
		}
		if firstSec == "" && r.Server != nil {
			firstSec = r.Server.String()
		}
		addObserved(r.Mapped)
		if r.Mapped.Port != mapped1.Port || !r.Mapped.IP.Equal(mapped1.IP) {
			if !differs {
				delta = r.Mapped.Port - mapped1.Port
			}
			differs = true
		}
	}

	for _, m := range <-obsCh {
		addObserved(m)
	}

	if differs {
		d.NATType = NatSymmetric
		d.Secondary = firstSec
		d.PortDelta = delta
		d.applyPattern(c.measurePattern())
		return d, nil
	}
	if answered {
		d.Secondary = firstSec
		if altAnswered {
			d.NATType = NatPortRestrictedCone
			d.FilterMeasured = true
		} else {
			d.NATType = NatCone
			d.Note = "inbound filter level untested: nothing answered from the server's second port"
		}
		return d, nil
	}

	d.NATType = NatUnmeasurable
	d.applyPattern(c.measurePattern())
	return d, nil
}

func (d *Detection) applyPattern(pat PortPattern) {
	d.PortStep = pat.PortStep
	d.PortPreserve = pat.PortPreserve
	d.PortPreserveOffset = pat.PortPreserveOffset

	// Combine allocation sample ports with observed STUN ports to tighten or
	// detect PBA port block boundaries when multiple samples were observed.
	sampleCount := len(pat.SamplePorts) + len(d.ObservedMappings)
	minP, maxP := pat.BlockMin, pat.BlockMax
	for _, m := range d.ObservedMappings {
		if m == nil || m.Port <= 0 {
			continue
		}
		if minP == 0 || m.Port < minP {
			minP = m.Port
		}
		if m.Port > maxP {
			maxP = m.Port
		}
	}
	if sampleCount >= 2 && minP > 0 && maxP >= minP && maxP-minP <= 2048 {
		d.PortBlockMin = minP
		d.PortBlockMax = maxP
	}
}
