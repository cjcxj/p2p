package stun

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestGuessGateway(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.168.1.23", "192.168.1.1"},
		{"10.7.3.23", "10.7.3.1"},
		{"192.168.1.1", ""}, // we are the gateway: asking ourselves is wrong
		{"127.0.0.1", ""},   // loopback has no gateway
		{"0.0.0.0", ""},     // unspecified
		{"2001:db8::1", ""}, // no v4 gateway guess from an IPv6 address
	}
	for _, c := range cases {
		got := guessGateway(net.ParseIP(c.in))
		if c.want == "" {
			if got != nil {
				t.Errorf("guessGateway(%s) = %v, want nil", c.in, got)
			}
			continue
		}
		if got == nil || got.String() != c.want {
			t.Errorf("guessGateway(%s) = %v, want %s", c.in, got, c.want)
		}
	}
}

func TestMapExternalUDPRejectsUnusablePort(t *testing.T) {
	for _, p := range []int{0, -1, 65536} {
		if a := MapExternalUDP(net.ParseIP("192.168.1.50"), p, 10*time.Millisecond); a != nil {
			t.Errorf("port %d returned %v, want nil", p, a)
		}
	}
	// Nothing to ask on a loopback-only host: no gateway is guessed and the IGD
	// discovery socket cannot bind, so the call must return nil fast rather than
	// sit out its whole budget.
	start := time.Now()
	if a := MapExternalUDP(net.IPv4(127, 0, 0, 1), 30000, 500*time.Millisecond); a != nil {
		t.Fatalf("loopback returned %v", a)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Logf("loopback took %v with no gateway to ask", d)
	}
}

// fakePMP answers the two NAT-PMP exchanges on the port the RFC reserves, so the
// wire format our client depends on is pinned rather than assumed.
func fakePMP(t *testing.T, extIP net.IP, extPort int) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5351})
	if err != nil {
		t.Skipf("cannot bind the NAT-PMP port on this machine: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			switch buf[1] {
			case 0: // public address query
				rep := make([]byte, 12)
				rep[1] = 128
				binary.BigEndian.PutUint16(rep[2:4], 0) // result code
				binary.BigEndian.PutUint32(rep[4:8], 1) // epoch
				copy(rep[8:12], extIP.To4())
				_, _ = c.WriteToUDP(rep, from)
			case 1: // UDP port mapping request
				rep := make([]byte, 16)
				rep[1] = 129
				binary.BigEndian.PutUint16(rep[2:4], 0) // result code
				binary.BigEndian.PutUint16(rep[8:10], binary.BigEndian.Uint16(buf[4:6]))
				binary.BigEndian.PutUint16(rep[10:12], uint16(extPort))
				binary.BigEndian.PutUint32(rep[12:16], 3600)
				_, _ = c.WriteToUDP(rep, from)
			}
		}
	}()
}

func TestMapNATPMPPinsWireFormat(t *testing.T) {
	ext := net.IPv4(203, 0, 113, 9)
	fakePMP(t, ext, 41000)

	got := mapNATPMP(net.IPv4(127, 0, 0, 1), 30000, 2*time.Second)
	if got == nil {
		t.Fatal("no mapping returned from a gateway that answered correctly")
	}
	if !got.IP.Equal(ext) || got.Port != 41000 {
		t.Fatalf("mapping is %s, want 203.0.113.9:41000", got)
	}
}

// A gateway that reports a failure result code must not be read as success: the
// public-address and mapping responses both carry a result we have to honour.
func TestMapNATPMPRespectsErrorCode(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5351})
	if err != nil {
		t.Skipf("cannot bind the NAT-PMP port on this machine: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 2 || buf[1] != 0 {
				continue
			}
			rep := make([]byte, 12)
			rep[1] = 128
			binary.BigEndian.PutUint16(rep[2:4], 2) // denied by the gateway's ACL
			_, _ = c.WriteToUDP(rep, from)
		}
	}()

	if got := mapNATPMP(net.IPv4(127, 0, 0, 1), 30000, 2*time.Second); got != nil {
		t.Fatalf("got %v from a gateway that denied the request", got)
	}
}
