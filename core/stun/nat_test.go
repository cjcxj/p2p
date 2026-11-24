package stun

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeResponder answers plain binding requests with a fixed mapped address.
// That is what a client sees through a NAT: the address the server reports has
// nothing to do with the socket the request came from.
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

// newFakeResponderOn serves an already bound socket, so a test can pin a
// responder to an exact port -- which the cone subtype needs, because the
// question "did the server answer from port+1?" is only well defined when the
// test controls what lives at port+1.
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
				continue // a single-port deployment stays silent
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

// newFakeResponderMapped is a responder that reports a chosen public IP (not
// just 127.0.0.1) so a test can emulate a destination-rotating CGNAT: the same
// client is seen at a different address by each observation point.
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
				continue // single-port, change-request stays silent
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
		Timeout:          400 * time.Millisecond,
		Secondaries:      secondaries,
		SecondaryTimeout: 400 * time.Millisecond,
	}
	det, err := c.Detect()
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	return det
}

// A STUN server that listens on one UDP port -- which is how a combined
// signaling+STUN+relay deployment normally runs -- cannot tell a symmetric NAT
// from a cone one by itself. Before the alternate-destination list existed,
// that case silently fell through to "port_restricted_cone" and every
// symmetric peer got the wrong punching plan.
// consecutiveResponders binds two responders on two adjacent UDP ports, which
// is how a test emulates "the server also answers from port+1".
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
		// The grade depends only on whether the server's own second port was
		// reachable, and here it was not: an unrelated host answered.
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

// Grading full vs address vs port restricted rests on the change-port test,
// and that test is only evidence when something can answer from the server's
// second port. A single-port deployment used to report every cone network as
// "port_restricted_cone", which is what made a home router look stricter than
// it is and hid whether a symmetric peer's first probe can reach it at all.
func TestConeSubtypeNeedsSecondServerPort(t *testing.T) {
	t.Run("second server port answers, subtype is graded", func(t *testing.T) {
		primary, altPort := consecutiveResponders(t, 42000, 42000)
		det := detectAgainst(t, primary, nil)
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
		dead.conn.Close() // leave primary.port+1 unanswered
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

// The generalization the deployment relies on: with several configured STUN
// observation points, a destination-rotating CGNAT is seen at a DIFFERENT public
// IP by each, and Detect must collect the whole candidate set (not just the
// primary). The easy peer sprays at every one of them, which is what turns a
// "we happened to sample the right IP" case into a configurable mechanism.
// ResolveAllUDPAddr must be safe with no DNS: an IPv4 literal resolves to
// itself (so adb-shell and offline paths are unaffected), and empty is nil.
func TestResolveAllUDPAddrLiteralSafe(t *testing.T) {
	got := ResolveAllUDPAddr("203.0.113.7:3478")
	if len(got) != 1 || got[0].IP.String() != "203.0.113.7" || got[0].Port != 3478 {
		t.Fatalf("literal IPv4 must resolve to itself, got %v", got)
	}
	if len(ResolveAllUDPAddr("")) != 0 {
		t.Fatal("empty must yield no addresses")
	}
}

func TestDetectCollectsMultiSTUNCandidateIPs(t *testing.T) {
	primary := newFakeResponderMapped(t, "203.0.113.212", 43000)
	s1 := newFakeResponderMapped(t, "203.0.113.216", 43000)
	s2 := newFakeResponderMapped(t, "203.0.113.220", 43000)
	dead := newFakeResponderMapped(t, "203.0.113.224", 43000)
	deadPort := dead.addr().Port
	dead.conn.Close() // an unreachable observation point must be skipped, not fatal

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
}
