// Package protocol defines the shared wire types used across the P2P stack:
// peer identifiers, signaling messages and NAT candidates.
package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// PeerID is a 16-byte random identifier assigned by the signaling server.
type PeerID [16]byte

// NewPeerID returns a fresh random peer identifier.
func NewPeerID() PeerID {
	var id PeerID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

// String renders the identifier as 32 lowercase hex characters.
func (id PeerID) String() string {
	return hex.EncodeToString(id[:])
}

// Less orders identifiers so both peers can elect the same role from the pair
// of IDs alone, without an extra round trip.
func (id PeerID) Less(other PeerID) bool {
	for i := range id {
		if id[i] != other[i] {
			return id[i] < other[i]
		}
	}
	return false
}

// ParsePeerID parses a 32-char hex string into a PeerID.
func ParsePeerID(s string) (PeerID, error) {
	var id PeerID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return id, errors.New("invalid peer id")
	}
	copy(id[:], b)
	return id, nil
}

// Signaling message types.
const (
	MsgHello     = "hello"
	MsgChallenge = "challenge"
	MsgAuth      = "auth"
	MsgAuthOK    = "auth_ok"
	MsgWelcome   = "welcome"
	MsgMembers   = "members"
	MsgCandidate = "candidate"
	MsgPing      = "ping"
	MsgError     = "error"
	MsgLeave     = "leave"
)

// MemberInfo describes one node of the virtual network.
type MemberInfo struct {
	PeerID    string `json:"peer_id"`
	VirtualIP string `json:"virtual_ip"`
}

// Candidate carries everything a peer needs to attempt hole punching
// against another peer.
type Candidate struct {
	PeerID      string `json:"peer_id"`
	VirtualIP   string `json:"virtual_ip"`
	NATType     string `json:"nat_type"`
	PublicAddr  string `json:"public_addr"`
	PrivateAddr string `json:"private_addr"`
	// ExtraPrivateAddrs carries the sender's other interface addresses (ip:port)
	// so a peer that shares one of them, but not the primary, still gets a
	// same-LAN path. Absent from older senders.
	ExtraPrivateAddrs []string `json:"extra_private_addrs,omitempty"`
	PortDelta         int      `json:"port_delta"`
	PortStep          int      `json:"port_step,omitempty"`
	// X25519Pub is the sender's X25519 public key (hex, 32 bytes) used to
	// derive a per-pair data-plane AEAD key. Older peers omit it and the
	// session falls back to plaintext data.
	X25519Pub string `json:"x25519_pub,omitempty"`
	// UPnPAddr is an externally mapped address the sender pinned on its own
	// gateway (NAT-PMP / UPnP IGD). Unlike a hole punched by traffic, it is
	// reachable before the sender sends anything, so a peer that learns it can
	// connect without waiting for a guess to collide. Empty for peers that have
	// no gateway mapping; older peers neither send nor read this field.
	UPnPAddr string `json:"upnp_addr,omitempty"`
	// PrivateCIDRs are the sender's interface subnets in CIDR form. Same-LAN
	// detection needs the real mask: a carrier link can be a /29 and a corporate
	// VLAN a /21, and comparing the first three octets gets both wrong. Peers
	// that predate this field simply fall back to the coarse comparison.
	PrivateCIDRs []string `json:"private_cidrs,omitempty"`
	// PortPreserve / PortPreserveOffset describe a measured port-preserving
	// allocator: the peer can then compute our mapped port from our local one
	// instead of searching for it. Omitted when the property was not measured.
	PortPreserve       bool `json:"port_preserve,omitempty"`
	PortPreserveOffset int  `json:"port_preserve_offset,omitempty"`
	// PortBlockMin/PortBlockMax bound the allocation block our NAT was measured to
	// hand ports from, letting a peer sweep that block instead of 1..65535.
	PortBlockMin int `json:"port_block_min,omitempty"`
	PortBlockMax int `json:"port_block_max,omitempty"`
}

// Message is the JSON-over-TCP wire frame exchanged over signaling.
type Message struct {
	Type      string       `json:"type"`
	Room      string       `json:"room,omitempty"`
	Token     string       `json:"token,omitempty"`
	PeerID    string       `json:"peer_id,omitempty"`
	VirtualIP string       `json:"virtual_ip,omitempty"`
	Network   string       `json:"network,omitempty"`
	Members   []MemberInfo `json:"members,omitempty"`
	Candidate *Candidate   `json:"candidate,omitempty"`
	User      string       `json:"user,omitempty"`
	Nonce     string       `json:"nonce,omitempty"`
	Proof     string       `json:"proof,omitempty"`
	Error     string       `json:"error,omitempty"`
}
