package stun

import (
	"fmt"
	"net"
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
	NatUnknown            NATType = "unknown"
	NatBlocked            NATType = "blocked"
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
}

// PublicAddr returns the mapped public address as a host:port string.
func (d *Detection) PublicAddr() string {
	if d.MappedAddr == nil {
		return ""
	}
	return d.MappedAddr.String()
}

// Secondary is an alternate STUN endpoint (second destination) used to
// detect symmetric NATs. It is optional.
func (c *Client) Secondary() *net.UDPAddr {
	if c.Server == nil {
		return nil
	}
	ip := c.Server.IP
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: c.Server.Port + 1}
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
// full-cone is conservatively reported as restricted-cone (the two behave
// identically for hole punching). A second IP on the server restores the
// distinction.
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

	// Test III: change port only -> filters by source port?
	t3, _, _ := c.BindRequest(false, true)
	if t3 != nil {
		// Not port-restricted in filtering: either full cone or
		// address-restricted cone.
		t2, _, _ := c.BindRequest(true, false)
		if t2 != nil {
			d.NATType = NatFullCone
		} else {
			d.NATType = NatRestrictedCone
		}
		return d, nil
	}

	// Filtering is port-dependent: either port-restricted cone or symmetric.
	// Probe a second destination to observe mapping behaviour.
	if sec := c.Secondary(); sec != nil {
		client2 := *c
		client2.Server = sec
		if t4, _, err4 := client2.BindOnce(); err4 == nil {
			if m4, errM := t4.MappedAddress(); errM == nil {
				if m4.Port != mapped1.Port {
					d.NATType = NatSymmetric
					d.PortDelta = m4.Port - mapped1.Port
					return d, nil
				}
			}
		}
	}
	d.NATType = NatPortRestrictedCone
	return d, nil
}
