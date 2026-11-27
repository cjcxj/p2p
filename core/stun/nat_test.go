package stun

import (
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResponder answers plain binding requests with a fixed mapped address.
type fakeResponder struct {
	conn       *net.UDPConn
	mappedPort int
	plainOnly  bool
}

func newFakeResponder(t *testing.T, mappedPort int, plainOnly bool) *fakeResponder {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return newFakeResponderOn(t, conn, mappedPort, plainOnly)
}

func newFakeResponderOn(t *testing.T, conn *net.UDPConn, mappedPort int, plainOnly bool) *fakeResponder {
	t.Helper()
	f := &fakeResponder{conn: conn, mappedPort: mappedPort, plainOnly: plainOnly}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := Decode(buf[:n])
			if err != nil || msg.Type != BindingRequest {
				continue
			}
			changeIP, changePort, ok := msg.ChangeRequest()
			if f.plainOnly && ok && (changeIP || changePort) {
				continue
			}
			resp := NewBindingSuccess(msg.TID)
			resp.SetXORMappedAddress(net.IPv4(127, 0, 0, 1), f.mappedPort)
			if ua, ok := src.(*net.UDPAddr); ok {
				conn.WriteToUDP(resp.Encode(), ua)
			}
		}
	}()
	return f
}

func (f *fakeResponder) addr() *net.UDPAddr {
	return f.conn.LocalAddr().(*net.UDPAddr)
}

func newFakeResponderMapped(t *testing.T, mappedIP string, mappedPort int) *fakeResponder {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	ip := net.ParseIP(mappedIP)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := Decode(buf[:n])
			if err != nil || msg.Type != BindingRequest {
				continue
			}
			if _, _, ok := msg.ChangeRequest(); ok {
				continue
			}
			resp := NewBindingSuccess(msg.TID)
			resp.SetXORMappedAddress(ip, mappedPort)
			if ua, ok := src.(*net.UDPAddr); ok {
				conn.WriteToUDP(resp.Encode(), ua)
			}
		}
	}()
	return &fakeResponder{conn: conn, mappedPort: mappedPort, plainOnly: true}
}

func (f *fakeResponder) hostPort() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(f.addr().Port))
}

func detectAgainst(t *testing.T, primary *fakeResponder, secondaries []string) *Detection {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer conn.Close()
	c := &Client{
		Conn:             conn,
		Server:           primary.addr(),
		Retries:          0,
		Timeout:          300 * time.Millisecond,
		Secondaries:      secondaries,
		SecondaryTimeout: 300 * time.Millisecond,
	}
	det, err := c.Detect()
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	return det
}

func consecutiveResponders(t *testing.T, mappedA, mappedB int) (*fakeResponder, *fakeResponder) {
	t.Helper()
	stride := int(time.Now().UnixNano()%900) * 2
	for port := 40000 + stride; port < 60000; port += 2 {
		ca, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			continue
		}
		cb, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port + 1})
		if err != nil {
			ca.Close()
			continue
		}
		a := newFakeResponderOn(t, ca, mappedA, true)
		b := newFakeResponderOn(t, cb, mappedB, true)
		t.Cleanup(func() { ca.Close(); cb.Close() })
		return a, b
	}
	t.Fatal("no two consecutive free UDP ports")
	return nil, nil
}

func TestDetectUsesAlternateDestinations(t *testing.T) {
	primary := newFakeResponder(t, 41000, true)

	t.Run("same mapping from a second destination is cone", func(t *testing.T) {
		alt := newFakeResponder(t, 41000, true)
		det := detectAgainst(t, primary, []string{alt.hostPort()})
		if det.NATType != NatCone && det.NATType != NatPortRestrictedCone {
			t.Fatalf("NAT type = %s, want a cone result (%s)", det.NATType, det.Method())
		}
		if det.Secondary != alt.addr().String() {
			t.Errorf("secondary = %q, want the destination that answered", det.Secondary)
		}
	})

	t.Run("different mapping per destination is symmetric", func(t *testing.T) {
		alt := newFakeResponder(t, 41012, true)
		det := detectAgainst(t, primary, []string{alt.hostPort()})
		if det.NATType != NatSymmetric {
			t.Fatalf("NAT type = %s, want %s", det.NATType, NatSymmetric)
		}
		if det.PortDelta != 12 {
			t.Errorf("port delta = %d, want 12", det.PortDelta)
		}
	})

	t.Run("no second destination is an unmeasured result, not a guess", func(t *testing.T) {
		dead := newFakeResponder(t, 41000, true)
		addr := dead.addr().Port
		dead.conn.Close()
		det := detectAgainst(t, primary, []string{fmt.Sprintf("127.0.0.1:%d", addr)})
		if det.NATType != NatUnmeasurable {
			t.Fatalf("NAT type = %s, want %s", det.NATType, NatUnmeasurable)
		}
		if det.Method() != "no alternate destination answered" {
			t.Errorf("method = %q", det.Method())
		}
	})

	t.Run("first reachable alternate decides", func(t *testing.T) {
		dead := newFakeResponder(t, 41000, true)
		deadPort := dead.addr().Port
		dead.conn.Close()
		alt := newFakeResponder(t, 41003, true)
		det := detectAgainst(t, primary, []string{
			fmt.Sprintf("127.0.0.1:%d", deadPort),
			alt.hostPort(),
		})
		if det.NATType != NatSymmetric || det.PortDelta != 3 {
			t.Fatalf("NAT type = %s delta = %d, want symmetric delta 3", det.NATType, det.PortDelta)
		}
	})
}

func TestConeSubtypeNeedsSecondServerPort(t *testing.T) {
	t.Run("second server port answers, subtype is graded", func(t *testing.T) {
		primary, altPort := consecutiveResponders(t, 42000, 42000)
		// Pass an empty non-nil list or local alt responder so sandbox does not
		// block waiting on unreachable public STUNs. Note secondaryAddrs uses
		// DefaultSecondaries when Secondaries is nil/empty, so pass altPort itself.
		det := detectAgainst(t, primary, []string{altPort.hostPort()})
		if det.NATType != NatPortRestrictedCone {
			t.Fatalf("NAT type = %s, want %s (%s)", det.NATType, NatPortRestrictedCone, det.Method())
		}
		if !det.FilterMeasured {
			t.Error("FilterMeasured = false, want the grade to be evidence-based")
		}
		if det.Secondary != altPort.addr().String() {
			t.Errorf("secondary = %q, want the server's second port", det.Secondary)
		}
	})

	t.Run("no second server port, subtype stays unmeasured", func(t *testing.T) {
		primary, dead := consecutiveResponders(t, 42000, 42000)
		dead.conn.Close()
		alt := newFakeResponder(t, 42000, true)
		det := detectAgainst(t, primary, []string{alt.hostPort()})
		if det.NATType != NatCone {
			t.Fatalf("NAT type = %s, want %s (%s)", det.NATType, NatCone, det.Method())
		}
		if det.FilterMeasured {
			t.Error("FilterMeasured = true, want the grade withheld")
		}
		if det.Note == "" {
			t.Error("Note empty, want the reason recorded")
		}
	})
}

func TestDetectCollectsMultiSTUNCandidateIPsAndMappings(t *testing.T) {
	primary := newFakeResponderMapped(t, "203.0.113.212", 43000)
	s1 := newFakeResponderMapped(t, "203.0.113.216", 43008)
	s2 := newFakeResponderMapped(t, "203.0.113.220", 43016)
	dead := newFakeResponderMapped(t, "203.0.113.224", 43024)
	deadPort := dead.addr().Port
	dead.conn.Close()

	det := detectAgainst(t, primary, []string{
		s1.hostPort(),
		fmt.Sprintf("127.0.0.1:%d", deadPort),
		s2.hostPort(),
	})

	if det.NATType != NatSymmetric {
		t.Fatalf("different egress IP per destination must classify symmetric, got %s", det.NATType)
	}
	seen := map[string]bool{}
	for _, ip := range det.ObservedIPs {
		seen[ip.String()] = true
	}
	for _, want := range []string{"203.0.113.212", "203.0.113.216", "203.0.113.220"} {
		if !seen[want] {
			t.Fatalf("candidate set missing %s; got %v", want, det.ObservedIPs)
		}
	}
	if seen["203.0.113.224"] {
		t.Fatal("unreachable observation point must not contribute a candidate")
	}
	if len(det.ObservedMappings) < 3 {
		t.Fatalf("expected >= 3 full observed mappings, got %v", det.ObservedMappings)
	}
}

func TestXORMappedIPv6RoundTrip(t *testing.T) {
	req := NewBindingRequest()
	resp := NewBindingSuccess(req.TID)
	ip6 := net.ParseIP("2001:db8:85a3::8a2e:370:7334")
	resp.SetXORMappedAddress(ip6, 51820)
	raw := resp.Encode()

	dec, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := dec.MappedAddress()
	if err != nil {
		t.Fatalf("MappedAddress: %v", err)
	}
	if !got.IP.Equal(ip6) || got.Port != 51820 {
		t.Fatalf("got %s, want [%s]:51820", got, ip6)
	}
}

func findFreePortBlock(t *testing.T, start, count int) int {
	t.Helper()
	for base := start; base < 32000-count; base += count {
		var conns []*net.UDPConn
		ok := true
		for i := 0; i < count; i++ {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: base + i})
			if err != nil {
				ok = false
				break
			}
			conns = append(conns, c)
		}
		for _, c := range conns {
			c.Close()
		}
		if ok {
			return base
		}
	}
	return start
}

func TestAnalyzeAllocationPatterns(t *testing.T) {
	startDynamicSTUN := func(t *testing.T, mapper func(srcPort int) int) *net.UDPAddr {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, src, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				msg, err := Decode(buf[:n])
				if err != nil || msg.Type != BindingRequest {
					continue
				}
				resp := NewBindingSuccess(msg.TID)
				resp.SetXORMappedAddress(net.IPv4(127, 0, 0, 1), mapper(src.Port))
				conn.WriteToUDP(resp.Encode(), src)
			}
		}()
		return conn.LocalAddr().(*net.UDPAddr)
	}

	t.Run("port preserving with offset", func(t *testing.T) {
		base := findFreePortBlock(t, 24000, 4)
		srv := startDynamicSTUN(t, func(srcPort int) int { return srcPort + 1000 })
		pat := AnalyzeAllocation(srv, base, 4, 300*time.Millisecond)
		if !pat.PortPreserve || pat.PortPreserveOffset != 1000 {
			t.Fatalf("expected PortPreserve offset +1000, got %+v", pat)
		}
	})

	t.Run("linear port step and PBA block", func(t *testing.T) {
		base := findFreePortBlock(t, 24100, 4)
		var seq atomic.Int32
		seq.Store(0)
		// Note: concurrent goroutines might arrive out of order, so base on
		// srcPort delta for deterministic step simulation.
		srv := startDynamicSTUN(t, func(srcPort int) int {
			return 45000 + (srcPort-base)*25
		})
		pat := AnalyzeAllocation(srv, base, 4, 300*time.Millisecond)
		if pat.PortStep != 25 {
			t.Fatalf("expected PortStep 25, got %+v", pat)
		}
		if pat.BlockMin != 45000 || pat.BlockMax != 45075 {
			t.Fatalf("expected PBA block 45000..45075, got %d..%d", pat.BlockMin, pat.BlockMax)
		}
	})
}

func TestResolveAllUDPAddr(t *testing.T) {
	addrs := ResolveAllUDPAddr("127.0.0.1:3478")
	if len(addrs) != 1 || addrs[0].String() != "127.0.0.1:3478" {
		t.Fatalf("literal IPv4 failed: %+v", addrs)
	}
	if got := ResolveAllUDPAddr(""); len(got) != 0 {
		t.Fatalf("empty input should return nil, got %+v", got)
	}
	local := ResolveAllUDPAddr("localhost:3478")
	if len(local) == 0 {
		t.Fatal("expected at least one resolved address for localhost:3478")
	}
}

func TestCoveringPoolRealUnicomSample(t *testing.T) {
	d := &Detection{
		MappedAddr: &net.UDPAddr{IP: net.ParseIP("111.55.212.114"), Port: 7857},
		ObservedIPs: []net.IP{
			net.ParseIP("111.55.212.114"),
			net.ParseIP("111.55.212.98"),
			net.ParseIP("111.55.212.110"),
			net.ParseIP("111.55.212.106"),
		},
	}
	pool := d.CoveringPool()
	if pool == nil {
		t.Fatal("clustered Unicom sample must yield a covering pool")
	}
	if ones, _ := pool.Mask.Size(); ones != 27 {
		t.Fatalf("Unicom sample should collapse to /27, got /%d (%s)", ones, pool)
	}
	for _, ip := range []string{"111.55.212.102", "111.55.212.114", "111.55.212.98"} {
		if !pool.Contains(net.ParseIP(ip)) {
			t.Fatalf("pool %s must contain %s", pool, ip)
		}
	}
}

func TestCoveringPoolIPStableSymmetric(t *testing.T) {
	d := &Detection{
		MappedAddr:  &net.UDPAddr{IP: net.ParseIP("223.104.80.77"), Port: 15684},
		ObservedIPs: []net.IP{net.ParseIP("223.104.80.77")},
	}
	if pool := d.CoveringPool(); pool != nil {
		t.Fatalf("single egress IP must not announce a pool, got %s", pool)
	}
}

func TestCoveringPoolWideSpreadRejected(t *testing.T) {
	d := &Detection{
		MappedAddr: &net.UDPAddr{IP: net.ParseIP("111.55.0.10"), Port: 12000},
		ObservedIPs: []net.IP{
			net.ParseIP("111.55.0.10"),
			net.ParseIP("111.55.16.10"), // spans /19, wider than /20 limit
		},
	}
	if pool := d.CoveringPool(); pool != nil {
		t.Fatalf("spread wider than /20 must return nil, got %s", pool)
	}
}

