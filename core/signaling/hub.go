package signaling

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"p2p/core/protocol"
)

// member is a connected peer inside a room.
type member struct {
	id   protocol.PeerID
	conn net.Conn
	vip  string
	mu   sync.Mutex // serialises writes to conn
}

// Room tracks members sharing a coordination context.
type Room struct {
	id        string
	token     string
	network   *net.IPNet
	usedIP    map[string]bool
	mu        sync.Mutex
	members   map[string]*member
}

// Hub manages rooms.
type Hub struct {
	mu         sync.Mutex
	rooms      map[string]*Room
	maxMembers int // 0 means unlimited
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{rooms: make(map[string]*Room)}
}

// SetMaxMembers caps the number of members per room. 0 disables the cap.
func (h *Hub) SetMaxMembers(n int) {
	h.mu.Lock()
	h.maxMembers = n
	h.mu.Unlock()
}

// ErrBadToken is returned when a room secret does not match.
var ErrBadToken = errors.New("signaling: room token mismatch")

// join adds a member to a room, creating it on first use. When the room is
// created the given token becomes its secret; later joiners must match it.
// network is the virtual subnet addresses are allocated from.
func (h *Hub) join(roomID, token string, m *member, network *net.IPNet) (vip string, created bool, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.rooms[roomID]
	if !ok {
		r = &Room{
			id:        roomID,
			token:     token,
			network:   network,
			usedIP:    make(map[string]bool),
			members:   make(map[string]*member),
		}
		h.rooms[roomID] = r
		created = true
	} else if r.token != "" && r.token != token {
		return "", false, ErrBadToken
	}
	if h.maxMembers > 0 && len(r.members) >= h.maxMembers {
		return "", created, fmt.Errorf("signaling: room %q is full", roomID)
	}
	if r.network != nil {
		vip, err = r.assignIP()
		if err != nil {
			return "", created, err
		}
	}
	m.vip = vip
	r.mu.Lock()
	r.members[m.id.String()] = m
	r.mu.Unlock()
	return vip, created, nil
}

// assignIP returns the next free host address in the subnet.
func (r *Room) assignIP() (string, error) {
	ones, bits := r.network.Mask.Size()
	if bits != 32 {
		return "", errors.New("signaling: only IPv4 subnets supported")
	}
	maxHosts := 1 << (32 - ones)
	if maxHosts > 256 {
		maxHosts = 256
	}
	for i := 1; i < maxHosts-1; i++ {
		ip := ipAt(r.network, i)
		if ip == nil {
			break
		}
		s := ip.String()
		if !r.usedIP[s] {
			r.usedIP[s] = true
			return s, nil
		}
	}
	return "", fmt.Errorf("signaling: no free address in %v", r.network)
}

// freeIP releases an address back to the pool.
func (r *Room) freeIP(ip string) {
	if ip != "" {
		delete(r.usedIP, ip)
	}
}

// ipAt computes the host-th address in a subnet (host is the offset added to
// the network base). Returns nil when the result falls outside the subnet.
func ipAt(n *net.IPNet, host int) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	add := host
	for j := len(ip) - 1; j >= 0 && add > 0; j-- {
		total := int(ip[j]) + add
		ip[j] = byte(total)
		add = total >> 8
	}
	if !n.Contains(ip) {
		return nil
	}
	return ip
}

// leave removes a member and returns the remaining member ids.
func (h *Hub) leave(roomID string, id protocol.PeerID) []string {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	key := id.String()
	r.mu.Lock()
	delete(r.members, key)
	var rest []string
	for k := range r.members {
		rest = append(rest, k)
	}
	r.mu.Unlock()
	return rest
}

// freeOnLeave releases the address of a departing member.
func (h *Hub) freeOnLeave(roomID string, id protocol.PeerID) {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if m := r.members[id.String()]; m != nil {
		r.freeIP(m.vip)
	}
}

// membersInfo returns the peer id + virtual ip of every member.
func (h *Hub) membersInfo(roomID string) []protocol.MemberInfo {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]protocol.MemberInfo, 0, len(r.members))
	for _, m := range r.members {
		out = append(out, protocol.MemberInfo{PeerID: m.id.String(), VirtualIP: m.vip})
	}
	return out
}

// networkOf returns the virtual subnet of a room.
func (h *Hub) networkOf(roomID string) string {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok || r.network == nil {
		return ""
	}
	return r.network.String()
}

// lookup returns a member of a room.
func (h *Hub) lookup(roomID string, id protocol.PeerID) *member {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.members[id.String()]
}

// broadcast sends a message to every member of a room except skip.
func (h *Hub) broadcast(roomID string, skip protocol.PeerID, m protocol.Message) {
	h.mu.Lock()
	r, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return
	}
	r.mu.Lock()
	mm := make([]*member, 0, len(r.members))
	for k, mem := range r.members {
		if k == skip.String() {
			continue
		}
		mm = append(mm, mem)
	}
	r.mu.Unlock()
	for _, mem := range mm {
		mem.mu.Lock()
		WriteMsg(mem.conn, m)
		mem.mu.Unlock()
	}
}

// sendTo delivers a message to one member of a room.
func (h *Hub) sendTo(roomID string, id protocol.PeerID, m protocol.Message) bool {
	mem := h.lookup(roomID, id)
	if mem == nil {
		return false
	}
	mem.mu.Lock()
	defer mem.mu.Unlock()
	return WriteMsg(mem.conn, m) == nil
}
