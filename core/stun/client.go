package stun

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Client performs STUN binding requests over a caller-supplied packet
// connection. Supplying the connection lets the client be used behind a real
// NAT.
type Client struct {
	Conn   net.PacketConn
	Server *net.UDPAddr
	// Retries is the number of times each request is re-sent (default 2).
	Retries int
	// Timeout is the per-request read deadline (default 2s).
	Timeout time.Duration
	// Secondaries overrides the alternate destinations used to test whether
	// this NAT maps each destination separately. Empty means DefaultSecondaries.
	Secondaries []string
	// SecondaryTimeout bounds one alternate-destination probe (default 800ms).
	// A public STUN may be blocked on this network, so this must stay small
	// even though it lengthens classification.
	SecondaryTimeout time.Duration
	// StepSamples is how many extra bindings Detect opens to learn the NAT's
	// port increment per new binding. Zero (the default) skips the measurement:
	// it costs one round trip per sample and only matters for symmetric NATs,
	// so callers that care opt in.
	StepSamples int
}

// DefaultSecondaries are public STUN servers used when the operator's own
// server answers on a single UDP port. Detecting a per-destination mapping
// needs a second destination; without one, a symmetric NAT is indistinguishable
// from a port-restricted cone and gets the wrong hole-punching plan.
// Both entries are reachable from Chinese carrier networks, where Google's
// STUN is normally dropped. The literal addresses are the A records those
// hostnames resolve to: inside a sandbox with no resolver (adb shell, some
// k8s pods) a hostname is useless, and a missing second destination silently
// turns a symmetric NAT into "unmeasurable".
var DefaultSecondaries = []string{
	"stun.miwifi.com:3478",
	"111.206.174.2:3478",
	"111.206.174.3:3478",
	"stun1.l.google.com:19302",
	"74.125.250.129:19302",
}

// BindRequest sends a binding request (optionally with a CHANGE-REQUEST) and
// waits for the matching response. It returns the response and the source
// address it arrived from.
func (c *Client) BindRequest(changeIP, changePort bool) (*Message, *net.UDPAddr, error) {
	req := NewBindingRequest()
	if changeIP || changePort {
		req.SetChangeRequest(changeIP, changePort)
	}
	req.AddSoftware("p2p")

	retries := c.Retries
	if retries <= 0 {
		retries = 2
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if _, err := c.Conn.WriteTo(req.Encode(), c.Server); err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(timeout)
		if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			dc.SetReadDeadline(deadline)
		}
		for {
			buf := make([]byte, 2048)
			n, src, err := c.Conn.ReadFrom(buf)
			if err != nil {
				if isTimeout(err) {
					break // retry
				}
				return nil, nil, err
			}
			if n < HeaderLength {
				continue
			}
			msg, err := Decode(buf[:n])
			if err != nil || msg.TID != req.TID {
				continue
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				ua = nil
			}
			return msg, ua, nil
		}
	}
	return nil, nil, errors.New("stun: no response")
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// BindOnce is a convenience wrapper for a single plain binding request.
func (c *Client) BindOnce() (*Message, *net.UDPAddr, error) {
	return c.BindRequest(false, false)
}

// secondaryProbe sends one plain binding request to an alternate destination.
// These probes are what separates a symmetric NAT from a cone one, and an
// alternate STUN is usually farther away than the operator's own server, so
// they get their own deadline rather than the tight one the primary
// classification uses. Worst case is SecondaryTimeout per candidate.
var errSecondaryBudget = errors.New("stun: alternate-probe budget exhausted")

func (c *Client) secondaryProbe(addr *net.UDPAddr, until time.Time) (*Message, error) {
	probe := *c
	probe.Server = addr
	// One resend: the first datagram still has the NAT binding to create and a
	// cellular path to a distant STUN server is slower than 800ms often enough
	// that a single-shot probe reports a reachable NAT as unmeasurable.
	probe.Retries = 1
	probe.Timeout = c.SecondaryTimeout
	if probe.Timeout <= 0 {
		probe.Timeout = 800 * time.Millisecond
	}
	if left := time.Until(until); left < probe.Timeout {
		if left <= 0 {
			return nil, errSecondaryBudget
		}
		probe.Timeout = left
	}
	msg, _, err := probe.BindRequest(false, false)
	return msg, err
}

// secondaryAddrs lists the alternate destinations to probe: the operator's own
// server one port above the primary, then the configured or built-in public
// STUN servers. A single-port deployment -- which is what a combined
// signaling+STUN+relay server normally is -- answers on the primary port only,
// so the public ones are what make symmetric detection work at all.
func (c *Client) secondaryAddrs() []*net.UDPAddr {
	list := c.Secondaries
	if len(list) == 0 {
		list = DefaultSecondaries
	}
	out := make([]*net.UDPAddr, 0, len(list)+1)
	seen := map[string]bool{}
	if c.Server != nil && c.Server.IP != nil {
		out = append(out, &net.UDPAddr{IP: c.Server.IP, Port: c.Server.Port + 1})
		seen[c.Server.String()] = true
	}
	for _, s := range list {
		// A hostname may carry several A records; probe each so one configured
		// multi-homed STUN contributes several observation destinations, widening
		// the enumerable egress pool on a rotating CGNAT.
		for _, addr := range ResolveAllUDPAddr(s) {
			if addr == nil {
				continue
			}
			k := addr.String()
			if k == seenKey(c.Server) || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, addr)
		}
	}
	return out
}

func seenKey(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// observeEgressIPs concurrently probes each alternate destination from its own
// ephemeral socket and returns every distinct public IP reported. This is the
// "configurable multi-STUN public probing" of the design: an operator can list
// many observation points and ALL of them are sampled in parallel (a sequential
// loop over a long list would be truncated by the detection budget). Each probe
// uses a separate socket so the whole sweep finishes in roughly one round trip,
// not one per server.
//
// It is used ONLY to widen the candidate IP set. NAT classification must still
// compare mappings for the SAME source socket (a symmetric NAT differs per
// destination; a fresh socket changes the mapping even on a cone NAT), so this
// never feeds the symmetric/cone decision -- only the spray target list.
func (c *Client) observeEgressIPs(addrs []*net.UDPAddr, per, budget time.Duration) []net.IP {
	if per <= 0 {
		per = 1200 * time.Millisecond
	}
	if budget <= 0 {
		budget = 4 * time.Second
	}
	type ev struct{ ip net.IP }
	ch := make(chan ev, len(addrs))
	var wg sync.WaitGroup
	deadline := time.Now().Add(budget)
	for _, a := range addrs {
		if a == nil || time.Now().After(deadline) {
			continue
		}
		if c.Server != nil && a.IP != nil && a.IP.Equal(c.Server.IP) && a.Port == c.Server.Port {
			continue // primary is already represented by MappedAddr
		}
		wg.Add(1)
		go func(dst *net.UDPAddr) {
			defer wg.Done()
			uc, err := net.ListenUDP("udp", nil)
			if err != nil {
				return
			}
			defer uc.Close()
			pc := &Client{Conn: uc, Server: dst, Retries: 0, Timeout: per}
			msg, _, err := pc.BindRequest(false, false)
			if err != nil {
				return
			}
			m, err := msg.MappedAddress()
			if err != nil || m.IP == nil {
				return
			}
			select {
			case ch <- ev{ip: m.IP}:
			default:
			}
		}(a)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var out []net.IP
	seen := map[string]bool{}
	for len(out) < len(addrs) {
		select {
		case e := <-ch:
			if !seen[e.ip.String()] {
				seen[e.ip.String()] = true
				out = append(out, e.ip)
			}
		case <-done:
			return out
		case <-time.After(time.Until(deadline)):
			return out
		}
	}
	return out
}
