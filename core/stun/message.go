// Package stun implements a minimal RFC 5389 STUN client/server plus a
// NAT behaviour classifier based on the classic RFC 3489 tests.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Type is a STUN message type.
type Type uint16

// STUN message types used by this package.
const (
	BindingRequest  Type = 0x0001
	BindingSuccess  Type = 0x0101
	BindingError    Type = 0x0111
)

// MagicCookie is the RFC 5389 fixed magic cookie.
const MagicCookie uint32 = 0x2112A442

// STUN attribute types used by this package.
const (
	AttrMappedAddress    uint16 = 0x0001
	AttrChangeRequest    uint16 = 0x0003
	AttrErrorCode        uint16 = 0x0009
	AttrXORMappedAddress uint16 = 0x0020
	AttrSoftware         uint16 = 0x8022
)

// Attribute is a single STUN attribute (type + value).
type Attribute struct {
	Type  uint16
	Value []byte
}

// Message is a STUN message.
type Message struct {
	Type  Type
	TID   [12]byte
	Attrs []Attribute
}

// NewBindingRequest returns a binding request with a random transaction id.
func NewBindingRequest() *Message {
	m := &Message{Type: BindingRequest}
	if _, err := rand.Read(m.TID[:]); err != nil {
		panic(err)
	}
	return m
}

// NewBindingSuccess builds a binding success response echoing the tid.
func NewBindingSuccess(tid [12]byte) *Message {
	return &Message{Type: BindingSuccess, TID: tid}
}

// Add appends an attribute.
func (m *Message) Add(t uint16, v []byte) *Message {
	m.Attrs = append(m.Attrs, Attribute{Type: t, Value: v})
	return m
}

// AddSoftware appends a SOFTWARE attribute.
func (m *Message) AddSoftware(name string) *Message {
	return m.Add(AttrSoftware, []byte(name))
}

// Get returns the first attribute of the given type.
func (m *Message) Get(t uint16) ([]byte, bool) {
	for _, a := range m.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// SetChangeRequest encodes a CHANGE-REQUEST attribute.
func (m *Message) SetChangeRequest(changeIP, changePort bool) *Message {
	var v uint32
	if changeIP {
		v |= 0x04
	}
	if changePort {
		v |= 0x02
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return m.Add(AttrChangeRequest, b)
}

// ChangeRequest decodes the CHANGE-REQUEST attribute, if present.
func (m *Message) ChangeRequest() (changeIP, changePort bool, ok bool) {
	v, ok := m.Get(AttrChangeRequest)
	if !ok || len(v) != 4 {
		return false, false, false
	}
	u := binary.BigEndian.Uint32(v)
	return u&0x04 != 0, u&0x02 != 0, true
}

// Encode serialises the message to its wire form.
func (m *Message) Encode() []byte {
	// attribute payload
	payload := make([]byte, 0, 128)
	for _, a := range m.Attrs {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:], a.Type)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(a.Value)))
		payload = append(payload, hdr...)
		payload = append(payload, a.Value...)
		for len(payload)%4 != 0 {
			payload = append(payload, 0)
		}
	}
	buf := make([]byte, HeaderLength+len(payload))
	binary.BigEndian.PutUint16(buf[0:], uint16(m.Type))
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)))
	binary.BigEndian.PutUint32(buf[4:], MagicCookie)
	copy(buf[8:], m.TID[:])
	copy(buf[HeaderLength:], payload)
	return buf
}

// HeaderLength is the STUN header size in bytes.
const HeaderLength = 20

// Decode parses a STUN message. It rejects messages shorter than the header
// or with an invalid magic cookie.
func Decode(b []byte) (*Message, error) {
	if len(b) < HeaderLength {
		return nil, errors.New("stun: message too short")
	}
	if binary.BigEndian.Uint32(b[4:8]) != MagicCookie {
		return nil, errors.New("stun: bad magic cookie")
	}
	mlen := int(binary.BigEndian.Uint16(b[2:4]))
	if HeaderLength+mlen > len(b) {
		return nil, errors.New("stun: truncated message")
	}
	m := &Message{
		Type: Type(binary.BigEndian.Uint16(b[0:2])),
	}
	copy(m.TID[:], b[8:20])
	body := b[HeaderLength : HeaderLength+mlen]
	for len(body) >= 4 {
		at := binary.BigEndian.Uint16(body[0:2])
		alen := int(binary.BigEndian.Uint16(body[2:4]))
		if alen > len(body)-4 {
			return nil, errors.New("stun: attribute overrun")
		}
		val := append([]byte(nil), body[4:4+alen]...)
		m.Attrs = append(m.Attrs, Attribute{Type: at, Value: val})
		body = body[4+alen:]
		// skip padding
		for len(body) > 0 && len(body)%4 != 0 {
			body = body[1:]
		}
	}
	return m, nil
}

// encodeAddr builds a MAPPED-ADDRESS style value.
func encodeAddr(family byte, ip net.IP, port uint16) []byte {
	v := make([]byte, 4+ipLen(ip))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], port)
	copy(v[4:], ip.To4())
	return v
}

func ipLen(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 16
}

// SetMappedAddress appends a MAPPED-ADDRESS attribute.
func (m *Message) SetMappedAddress(ip net.IP, port int) *Message {
	v := encodeAddr(0x01, ip, uint16(port))
	return m.Add(AttrMappedAddress, v)
}

// SetXORMappedAddress appends an XOR-MAPPED-ADDRESS attribute.
func (m *Message) SetXORMappedAddress(ip net.IP, port int) *Message {
	ip = ip.To4()
	if ip == nil {
		ip = ip.To16()
	}
	p := uint16(port) ^ uint16(MagicCookie>>16)
	family := byte(0x01)
	if len(ip) == 16 {
		family = 0x02
	}
	v := make([]byte, 4+len(ip))
	v[1] = family
	binary.BigEndian.PutUint16(v[2:4], p)
	xorKey := [4]byte{byte((MagicCookie >> 24) & 0xff), byte((MagicCookie >> 16) & 0xff), byte((MagicCookie >> 8) & 0xff), byte(MagicCookie & 0xff)}
	for i := 0; i < len(ip); i++ {
		v[4+i] = ip[i] ^ xorKey[i%4]
	}
	return m.Add(AttrXORMappedAddress, v)
}

// MappedAddress returns the (possibly XOR-)mapped address contained in the
// message, preferring XOR-MAPPED-ADDRESS.
func (m *Message) MappedAddress() (*net.UDPAddr, error) {
	for _, at := range []uint16{AttrXORMappedAddress, AttrMappedAddress} {
		v, ok := m.Get(at)
		if !ok {
			continue
		}
		addr, err := parseAddr(v, at == AttrXORMappedAddress, m.TID[:])
		if err != nil {
			return nil, err
		}
		return addr, nil
	}
	return nil, errors.New("stun: no mapped address attribute")
}

// parseAddr decodes a MAPPED-ADDRESS / XOR-MAPPED-ADDRESS value.
func parseAddr(v []byte, xor bool, tid []byte) (*net.UDPAddr, error) {
	if len(v) < 4 {
		return nil, errors.New("stun: short address")
	}
	family := v[1]
	var port uint16
	if xor {
		port = binary.BigEndian.Uint16(v[2:4]) ^ uint16(MagicCookie>>16)
	} else {
		port = binary.BigEndian.Uint16(v[2:4])
	}
	alen := 4
	if family == 0x02 {
		alen = 16
	}
	if len(v) < 4+alen {
		return nil, errors.New("stun: short address body")
	}
	ip := make(net.IP, alen)
	copy(ip, v[4:4+alen])
	if xor {
		key := [4]byte{byte((MagicCookie >> 24) & 0xff), byte((MagicCookie >> 16) & 0xff), byte((MagicCookie >> 8) & 0xff), byte(MagicCookie & 0xff)}
		for i := 0; i < len(ip); i++ {
			ip[i] ^= key[i%4]
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// ErrorCode returns the RFC 3489 error class and number, if present.
func (m *Message) ErrorCode() (int, int, bool) {
	v, ok := m.Get(AttrErrorCode)
	if !ok || len(v) < 4 {
		return 0, 0, false
	}
	return int(v[2] & 0x07), int(v[3]), true
}

// ResolveUDPAddr is a small helper used to normalise host:port strings.
func ResolveUDPAddr(addr string) (*net.UDPAddr, error) {
	if addr == "" {
		return nil, fmt.Errorf("stun: empty address")
	}
	return net.ResolveUDPAddr("udp", addr)
}
