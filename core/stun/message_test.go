package stun

import (
	"encoding/binary"
	"net"
	"testing"
)

// An IPv6 reflex address used to encode as a family-0x01 attribute with an empty
// body: SetXORMappedAddress assigned ip = ip.To4() and then "fell back" to
// ip.To16() on the nil result, which is still nil, so the address vanished from
// our own server's Binding Success. The mask also has to be RFC 8489 §14.2's
// magic cookie followed directly by the 96-bit transaction id -- an earlier
// version of this file, and the copy still on the candidate branch, kept four zero
// bytes in between, which no conformant peer reads.
func TestXORMappedAddressIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if ip == nil {
		t.Fatal("bad test address")
	}
	m := &Message{Type: BindingSuccess}
	m.TID = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	m.SetXORMappedAddress(ip, 7000)

	v, ok := m.Get(AttrXORMappedAddress)
	if !ok {
		t.Fatal("no XOR-MAPPED-ADDRESS emitted")
	}
	if len(v) != 4+16 {
		t.Fatalf("attribute body %d bytes, want 20 (header + 16-byte address)", len(v))
	}
	if v[1] != 0x02 {
		t.Fatalf("family %#02x, want 0x02 for IPv6", v[1])
	}

	key := make([]byte, 16)
	binary.BigEndian.PutUint32(key[0:4], MagicCookie)
	copy(key[4:], m.TID[:])
	want := ip.To16()
	for i := range want {
		if v[4+i] != want[i]^key[i] {
			t.Fatalf("address byte %d = %#02x, want %#02x (mask is not cookie||0||TID)",
				i, v[4+i], want[i]^key[i])
		}
	}
	if got := binary.BigEndian.Uint16(v[2:4]); got != uint16(7000)^uint16(MagicCookie>>16) {
		t.Fatalf("xorted port %#04x, want %#04x", got, uint16(7000)^uint16(MagicCookie>>16))
	}

	got, err := m.MappedAddress()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.IP.Equal(ip) || got.Port != 7000 {
		t.Fatalf("round trip gave %s, want [2001:db8::1]:7000", got)
	}
}

func TestXORMappedAddressIPv4(t *testing.T) {
	ip := net.IPv4(203, 0, 113, 7)
	m := &Message{Type: BindingSuccess}
	m.TID = [12]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	m.SetXORMappedAddress(ip, 5000)

	v, ok := m.Get(AttrXORMappedAddress)
	if !ok {
		t.Fatal("no XOR-MAPPED-ADDRESS emitted")
	}
	if len(v) != 4+4 {
		t.Fatalf("attribute body %d bytes, want 8", len(v))
	}
	if v[1] != 0x01 {
		t.Fatalf("family %#02x, want 0x01 for IPv4", v[1])
	}
	// IPv4 masks with the bare cookie, which is the one case where the repeating
	// mask happened to be right -- pin it so a future "unify the two" edit does
	// not break interop.
	want := ip.To4()
	for i := range want {
		if v[4+i] != want[i]^[4]byte{0x21, 0x12, 0xa4, 0x42}[i] {
			t.Fatalf("address byte %d = %#02x, want %#02x", i, v[4+i], want[i]^[4]byte{0x21, 0x12, 0xa4, 0x42}[i])
		}
	}
	got, err := m.MappedAddress()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.IP.Equal(ip) || got.Port != 5000 {
		t.Fatalf("round trip gave %s, want 203.0.113.7:5000", got)
	}
}

// MAPPED-ADDRESS (the legacy, un-xorred form) carried the same copy bug: it wrote
// ip.To4() into a 16-byte field, which for IPv6 is nil, i.e. all zeroes.
func TestMappedAddressKeepsIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::abcd")
	m := &Message{Type: BindingSuccess}
	m.SetMappedAddress(ip, 4004)

	v, ok := m.Get(AttrMappedAddress)
	if !ok {
		t.Fatal("no MAPPED-ADDRESS emitted")
	}
	if len(v) != 4+16 || v[1] != 0x02 {
		t.Fatalf("attribute is %d bytes family %#02x, want 20 bytes family 0x02", len(v), v[1])
	}
	for i, b := range ip.To16() {
		if v[4+i] != b {
			t.Fatalf("address byte %d = %#02x, want %#02x", i, v[4+i], b)
		}
	}
}
