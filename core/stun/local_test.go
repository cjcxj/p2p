package stun

import (
	"net"
	"testing"
)

func TestEnumerateLocalAddrs(t *testing.T) {
	primary := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	addrs, cidrs := enumerateLocalAddrs(30000, primary)
	if len(addrs) == 0 {
		t.Fatal("no addresses, want at least the primary")
	}
	if !addrs[0].IP.Equal(primary.IP) {
		t.Fatalf("first address is %v, want the primary %v first", addrs[0], primary)
	}
	for _, a := range addrs {
		if a.Port != 30000 {
			t.Fatalf("address %v lost the socket port", a)
		}
		if a.IP.To4() == nil || a.IP.IsLoopback() {
			t.Fatalf("address %v is not a usable IPv4 interface address", a)
		}
	}
	for _, c := range cidrs {
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("subnet %q does not parse: %v", c, err)
		}
		if ip.To4() == nil {
			t.Fatalf("subnet %q is not IPv4", c)
		}
		if n.IP.String() != ip.String() {
			// A host address paired with a prefix is normal CIDR notation here
			// ("192.168.1.5/24"), so only reject a mask that cannot hold the IP.
			if !n.Contains(ip) {
				t.Fatalf("subnet %q does not contain its own address", c)
			}
		}
	}
	// No port means nothing to advertise: the whole point is "this port, on those
	// interfaces".
	if a, c := enumerateLocalAddrs(0, primary); a != nil || c != nil {
		t.Fatalf("port 0 produced %v / %v, want nothing", a, c)
	}
}
