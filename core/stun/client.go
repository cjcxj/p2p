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
	// SecondaryTimeout bounds one alternate-destination sweep (default 800ms).
	SecondaryTimeout time.Duration
	// StepSamples is how many extra bindings Detect opens to learn the NAT's
	// port allocation behaviour (step, port-preserving offset, PBA block).
	StepSamples int
}

// DefaultSecondaries are public STUN servers used when the operator's own
// server answers on a single UDP port. Multiple observation points allow
// concurrent symmetric NAT detection and discovery of rotating CGNAT egress IPs.
var DefaultSecondaries = []string{
	"stun.miwifi.com:3478",
	"111.206.174.2:3478",
	"111.206.174.3:3478",
	"stun.qq.com:3478",
	"stun1.l.google.com:19302",
	"74.125.250.129:19302",
}

// DefaultIPv6Secondaries are dual-stack / IPv6 public STUN servers used when
// probing IPv6 public reachability.
var DefaultIPv6Secondaries = []string{
	"stun1.l.google.com:19302",
	"stun.l.google.com:19302",
}

// STUNResult captures one valid STUN BindingResponse from a destination.
type STUNResult struct {
	Server  *net.UDPAddr
	Mapped  *net.UDPAddr
	From    *net.UDPAddr
	Latency time.Duration
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
	if retries < 0 {
		retries = 0
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		defer dc.SetReadDeadline(time.Time{})
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if _, err := c.Conn.WriteTo(req.Encode(), c.Server); err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(timeout)
		if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dc.SetReadDeadline(deadline)
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
			ua, _ := src.(*net.UDPAddr)
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

// ConcurrentBindAll sends STUN BindingRequests concurrently to all destinations
// in addrs over c.Conn, demultiplexing responses by Transaction ID. It returns
// early as soon as every destination has answered, or when timeout elapses.
func (c *Client) ConcurrentBindAll(addrs []*net.UDPAddr, timeout time.Duration) []STUNResult {
	if c.Conn == nil || len(addrs) == 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}

	type pendingReq struct {
		dst    *net.UDPAddr
		packet []byte
		sentAt time.Time
		done   bool
	}

	pending := make(map[[12]byte]*pendingReq, len(addrs))
	order := make([][12]byte, 0, len(addrs))
	for _, dst := range addrs {
		if dst == nil {
			continue
		}
		req := NewBindingRequest()
		req.AddSoftware("p2p")
		raw := req.Encode()
		pending[req.TID] = &pendingReq{
			dst:    dst,
			packet: raw,
			sentAt: time.Now(),
		}
		order = append(order, req.TID)
		_, _ = c.Conn.WriteTo(raw, dst)
	}
	if len(pending) == 0 {
		return nil
	}

	if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		defer dc.SetReadDeadline(time.Time{})
	}

	results := make([]STUNResult, 0, len(pending))
	answered := 0
	start := time.Now()
	overallDeadline := start.Add(timeout)
	retryAt := start.Add(timeout / 2)
	retried := false

	buf := make([]byte, 2048)
	for answered < len(pending) {
		now := time.Now()
		if !now.Before(overallDeadline) {
			break
		}
		nextDeadline := overallDeadline
		if !retried && retryAt.Before(nextDeadline) {
			nextDeadline = retryAt
		}
		if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dc.SetReadDeadline(nextDeadline)
		}

		n, src, err := c.Conn.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				if !retried && !time.Now().Before(retryAt) {
					retried = true
					for _, tid := range order {
						pr := pending[tid]
						if !pr.done {
							pr.sentAt = time.Now()
							_, _ = c.Conn.WriteTo(pr.packet, pr.dst)
						}
					}
					continue
				}
				break
			}
			break
		}
		if n < HeaderLength {
			continue
		}
		msg, err := Decode(buf[:n])
		if err != nil {
			continue
		}
		pr, ok := pending[msg.TID]
		if !ok || pr.done {
			continue
		}
		mapped, err := msg.MappedAddress()
		if err != nil {
			continue
		}
		pr.done = true
		answered++
		ua, _ := src.(*net.UDPAddr)
		results = append(results, STUNResult{
			Server:  pr.dst,
			Mapped:  mapped,
			From:    ua,
			Latency: time.Since(pr.sentAt),
		})
	}
	return results
}

// secondaryAddrs lists the alternate destinations to probe: the operator's own
// server one port above the primary, then the configured or built-in STUN
// servers.
func (c *Client) secondaryAddrs() []*net.UDPAddr {
	list := c.Secondaries
	if len(list) == 0 {
		list = DefaultSecondaries
	}
	seen := make(map[string]bool, len(list)+2)
	out := make([]*net.UDPAddr, 0, len(list)+1)

	addUnique := func(a *net.UDPAddr) {
		if a == nil || a.IP == nil {
			return
		}
		if c.Server != nil && a.IP.Equal(c.Server.IP) && a.Port == c.Server.Port {
			return
		}
		k := a.String()
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, a)
	}

	if c.Server != nil && c.Server.IP != nil && c.Server.Port > 0 && c.Server.Port < 65535 {
		addUnique(&net.UDPAddr{IP: c.Server.IP, Port: c.Server.Port + 1})
	}
	for _, s := range list {
		for _, addr := range ResolveAllUDPAddr(s) {
			if addr == nil {
				continue
			}
			// Keep IPv4 probes on the IPv4 detection path; IPv6 is probed separately.
			if c.Server != nil && c.Server.IP != nil {
				isV4Server := c.Server.IP.To4() != nil
				isV4Addr := addr.IP.To4() != nil
				if isV4Server != isV4Addr {
					continue
				}
			}
			addUnique(addr)
		}
	}
	return out
}

// ObserveEgress concurrently probes each alternate destination from its own
// ephemeral socket and returns every distinct public UDP address (IP+Port)
// reported. Collecting both IP and Port captures both rotating CGNAT egress IPs
// and Port Block Allocation (PBA) clustering across destinations.
func (c *Client) ObserveEgress(addrs []*net.UDPAddr, per, budget time.Duration) []*net.UDPAddr {
	if len(addrs) == 0 {
		return nil
	}
	if per <= 0 {
		per = 700 * time.Millisecond
	}
	if budget <= 0 {
		budget = 900 * time.Millisecond
	}
	ch := make(chan *net.UDPAddr, len(addrs))
	var wg sync.WaitGroup
	deadline := time.Now().Add(budget)
	for _, a := range addrs {
		if a == nil || time.Now().After(deadline) {
			continue
		}
		if c.Server != nil && a.IP != nil && a.IP.Equal(c.Server.IP) && a.Port == c.Server.Port {
			continue
		}
		wg.Add(1)
		go func(dst *net.UDPAddr) {
			defer wg.Done()
			uc, err := net.ListenUDP("udp4", nil)
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
			case ch <- m:
			default:
			}
		}(a)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var out []*net.UDPAddr
	seen := map[string]bool{}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for len(out) < len(addrs) {
		select {
		case m := <-ch:
			k := m.String()
			if !seen[k] {
				seen[k] = true
				out = append(out, m)
			}
		case <-done:
			for {
				select {
				case m := <-ch:
					k := m.String()
					if !seen[k] {
						seen[k] = true
						out = append(out, m)
					}
				default:
					return out
				}
			}
		case <-timer.C:
			return out
		}
	}
	return out
}

// observeEgressIPs is kept for callers that only need distinct egress IPs.
func (c *Client) observeEgressIPs(addrs []*net.UDPAddr, per, budget time.Duration) []net.IP {
	mappings := c.ObserveEgress(addrs, per, budget)
	var out []net.IP
	seen := map[string]bool{}
	for _, m := range mappings {
		if m != nil && m.IP != nil && !seen[m.IP.String()] {
			seen[m.IP.String()] = true
			out = append(out, m.IP)
		}
	}
	return out
}

// ProbeIPv6 attempts a fast STUN probe over IPv6 to learn if this host has a
// globally reachable IPv6 UDP address. Non-fatal and bounded by timeout.
func ProbeIPv6(servers []string, timeout time.Duration) *net.UDPAddr {
	if len(servers) == 0 {
		servers = DefaultIPv6Secondaries
	}
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	var addrs []*net.UDPAddr
	for _, s := range servers {
		a, err := net.ResolveUDPAddr("udp6", s)
		if err != nil || a.IP == nil || a.IP.To4() != nil {
			continue
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil
	}
	c := &Client{Conn: conn}
	res := c.ConcurrentBindAll(addrs, timeout)
	for _, r := range res {
		if r.Mapped != nil && r.Mapped.IP != nil && r.Mapped.IP.IsGlobalUnicast() {
			return r.Mapped
		}
	}
	return nil
}
