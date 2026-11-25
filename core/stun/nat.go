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
	// NatCone means the NAT repeats one mapping for every destination (so it is
	// cone, which is all hole punching needs to know) but the inbound filter
	// level was never measured: grading full vs address vs port restricted
	// requires the server to answer from a second port and a second IP, and a
	// combined server normally has neither. Reporting a guessed subtype is what
	// made a single-port deployment claim "port restricted" everywhere.
	NatCone NATType = "cone"
	// NatUnmeasurable means filtering was at least port-dependent, but no
	// alternate destination answered, so cone and symmetric were never told
	// apart. Treat it as "may well be symmetric", not as cone.
	NatUnmeasurable NATType = "unmeasurable"
	NatUnknown      NATType = "unknown"
	NatBlocked      NATType = "blocked"
)

// Detection holds the result of a NAT classification.
type Detection struct {
	NATType NATType
	// MappedAddr is the public mapping observed for the primary STUN server.
	MappedAddr *net.UDPAddr
	// LocalAddr is the address of the client socket.
	LocalAddr *net.UDPAddr
	// PortDelta is the per-mapping port increment observed for a symmetric
	// NAT (0 when not symmetric or not measurable).
	PortDelta int
	// Secondary records which alternate destination produced the comparison
	// that decided a symmetric/port-restricted classification. Empty means no
	// alternate destination was usable.
	Secondary string
	// PortStep is how far this NAT's public port moves per new binding
	// (0 = not measured or not predictable). It is the number symmetric NAT
	// port prediction needs: the increment is per binding, not per destination,
	// so it can only be learned by creating several sockets.
	PortStep int
	// ObservedIPs is the set of distinct public IPv4 addresses this host was
	// seen at across the primary and every alternate destination that answered
	// (index 0 is the primary mapping). A CGNAT that rotates its egress address
	// per destination yields several; the easy peer sprays at all of them so a
	// destination-dependent mapping can still be collided with.
	ObservedIPs []net.IP
	// FilterMeasured reports whether the cone subtype (full / address / port
	// restricted) was actually observed rather than assumed.
	FilterMeasured bool
	// Note carries the caveat for what could not be tested, so a reader of the
	// log knows how far to trust NATType.
	Note string
}

// PublicAddr returns the mapped public address as a host:port string.
func (d *Detection) PublicAddr() string {
	if d.MappedAddr == nil {
		return ""
	}
	return d.MappedAddr.String()
}

// CoveringPool returns the smallest IPv4 prefix that contains the mapped
// address and every observed egress address. A destination-rotating CGNAT only
// shows STUN a few of the public IPs in its contiguous block, so the address it
// uses toward a particular peer is often absent from the sample -- but the
// block is inferable from the clustered samples. Advertising this prefix lets
// the easy peer spray the whole block instead of guessing the one egress IP.
// Returns nil when there is nothing to expand (fewer than two distinct IPv4
// addresses) or when the samples are too far apart to be one carrier block
// (covering prefix shorter than /20), so an absurd range is never announced.
func (d *Detection) CoveringPool() *net.IPNet {
	if d.MappedAddr == nil {
		return nil
	}
	ips := make([]net.IP, 0, len(d.ObservedIPs)+1)
	seen := map[string]bool{}
	add := func(ip net.IP) {
		ip4 := ip.To4()
		if ip4 == nil || seen[ip4.String()] {
			return
		}
		seen[ip4.String()] = true
		ips = append(ips, ip4)
	}
	if d.MappedAddr != nil {
		add(d.MappedAddr.IP)
	}
	for _, ip := range d.ObservedIPs {
		add(ip)
	}
	if len(ips) < 2 {
		return nil
	}
	first := u32(ips[0])
	var diff uint32
	for _, ip := range ips[1:] {
		diff |= first ^ u32(ip)
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
	base := net.IPv4(byte(first>>24), byte(first>>16), byte(first>>8), byte(first)).Mask(mask)
	return &net.IPNet{IP: base, Mask: mask}
}

func u32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// Method explains what the classification actually rested on, which is the
// first thing to look at when a peer's punching plan seems wrong: a symmetric
// NAT only ever shows up if an alternate destination answered.
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
	if d.PortStep != 0 {
		s += fmt.Sprintf("; port step %+d per new binding", d.PortStep)
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

// Detect runs the RFC 3489 style test sequence and classifies the NAT.
//
// With a single-IP STUN server the change-IP test is never answered, so
// full-cone is conservatively reported as port-restricted cone (the two behave
// the same for hole punching). The cone/symmetric distinction does not depend
// on the server having a second port: an alternate destination from
// DefaultSecondaries is enough, and if none of them answers the result is
// NatUnmeasurable rather than a guess.
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
	// A socket bound to 0.0.0.0 reports a wildcard local IP. Resolve the
	// concrete source IP used to reach the STUN server so same-LAN peers can
	// find each other via the private-network shortcut.
	if localUDP != nil && (localUDP.IP == nil || localUDP.IP.IsUnspecified()) {
		if ip := localIPFor(c.Server); ip != nil {
			localUDP = &net.UDPAddr{IP: ip, Port: localUDP.Port}
		}
	}
	d := &Detection{
		NATType:    NatUnknown,
		MappedAddr: mapped1,
		LocalAddr:  localUDP,
	}

	// Not behind a NAT: public mapping equals local socket address.
	if localUDP != nil && mapped1.IP.Equal(localUDP.IP) && mapped1.Port == localUDP.Port {
		d.NATType = NatOpen
		return d, nil
	}

	// Test III: ask the server to answer from its port+1. A reply proves the
	// NAT does not filter by source port. Silence proves nothing on its own:
	// a combined signaling+STUN+relay server usually listens on one UDP port
	// only, so there may be nobody to answer from port+1 even on a full-cone
	// network. The alternate loop below records whether server:port+1 ever
	// answered and grades the cone subtype from that instead of guessing.
	t3, _, _ := c.BindRequest(false, true)
	if t3 != nil {
		// Not port-filtered. Telling full cone from address-restricted cone
		// needs a reply from a *second server address*, which a single-address
		// deployment cannot produce.
		t2, _, _ := c.BindRequest(true, false)
		if t2 != nil {
			d.NATType = NatFullCone
			d.FilterMeasured = true
		} else {
			d.NATType = NatCone
			d.Note = "not port-filtered; full vs address-restricted needs a second server address"
		}
		return d, nil
	}

	// Filtering is port-dependent: either port-restricted cone or symmetric.
	// Ask the alternate destinations what they see. A cone NAT repeats the
	// mapping it already made, a symmetric / CGNAT allocates a new one per
	// destination. That per-destination address is exactly what the easy peer
	// must aim at, so keep probing every alternate (within a budget) to publish
	// the whole candidate set, not only the first one that answers. Any answer
	// that differs from the primary mapping proves the NAT is destination-
	// dependent, which is the correct trigger for the plant/spray strategy.
	until := time.Now().Add(6 * time.Second)
	altAnswered := false
	answered := false
	differs := false
	delta := 0
	firstSec := ""
	observed := []net.IP{}
	seen := map[string]bool{}
	if mapped1.IP != nil {
		seen[mapped1.IP.String()] = true
		observed = append(observed, mapped1.IP)
	}
	// Enumerate the whole configured STUN list in parallel (from ephemeral
	// sockets) while the shared-socket classification runs below. This is what
	// makes "configure many STUN servers" actually sample them all instead of
	// the first few the sequential budget reaches.
	altAddrs := c.secondaryAddrs()
	obsDone := make(chan []net.IP, 1)
	go func() { obsDone <- c.observeEgressIPs(altAddrs, 1200*time.Millisecond, 4*time.Second) }()
	for _, sec := range altAddrs {
		if time.Now().After(until) {
			break
		}
		fromServerAltPort := c.Server != nil && sec.IP != nil &&
			sec.IP.Equal(c.Server.IP) && sec.Port == c.Server.Port+1
		t4, err4 := c.secondaryProbe(sec, until)
		if err4 != nil {
			continue
		}
		m4, errM := t4.MappedAddress()
		if errM != nil {
			continue
		}
		answered = true
		if fromServerAltPort {
			altAnswered = true
		}
		if firstSec == "" {
			firstSec = sec.String()
		}
		if m4.IP != nil && !seen[m4.IP.String()] {
			seen[m4.IP.String()] = true
			observed = append(observed, m4.IP)
		}
		if m4.Port != mapped1.Port || !m4.IP.Equal(mapped1.IP) {
			if !differs {
				delta = m4.Port - mapped1.Port
			}
			differs = true
		}
	}
	// Fold in every egress IP the parallel multi-STUN sweep found, so the
	// published candidate set covers the full configured observation list.
	for _, ip := range <-obsDone {
		if ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			observed = append(observed, ip)
		}
	}
	d.ObservedIPs = observed
	if differs {
		d.NATType = NatSymmetric
		d.Secondary = firstSec
		d.PortDelta = delta
		d.PortStep = c.measureStep()
		return d, nil
	}
	if answered {
		d.Secondary = firstSec
		// Cone: every alternate that answered repeated the primary mapping.
		// Grading the inbound filter needs the change-port test to have been
		// possible, and the only evidence that it was is the server's second
		// port answering.
		if altAnswered {
			d.NATType = NatPortRestrictedCone
			d.FilterMeasured = true
		} else {
			d.NATType = NatCone
			d.Note = "inbound filter level untested: nothing answered from the server's second port"
		}
		return d, nil
	}

	// No alternate destination answered, so the mapping was never observed
	// against a second destination. Guessing "port restricted" here is what
	// makes a symmetric NAT get the wrong punching plan: report the ambiguity
	// and let the strategy probe for both.
	d.NATType = NatUnmeasurable
	d.PortStep = c.measureStep()
	return d, nil
}
