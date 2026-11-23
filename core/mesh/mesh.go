// Package mesh implements the virtual-network layer on top of the punch
// engine's direct links: virtual addresses, flooding-based multi-hop routing,
// broadcast/multicast emulation, and loop-free forwarding.
//
// Frames are flooded when no direct link to the destination is known, with a
// hop limit and a per-origin packet id for deduplication, so any connected
// topology routes correctly.
package mesh

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"p2p/core/protocol"
)

// Magic marks every mesh frame carried inside a punch data packet.
const Magic = 0x4D53484D // "MSHM"

// frameHeaderLen is the fixed mesh frame header size.
const frameHeaderLen = 4 + 1 + 1 + 4 + 16 + 16

// Frame flags.
const (
	flagBroadcast uint8 = 0x01
)

// MaxTTL bounds the number of hops a frame may travel.
const MaxTTL = 16

// Frame is a routed mesh frame.
type Frame struct {
	Broadcast bool
	Src       net.IP
	Dst       net.IP
	PktID     uint32
	TTL       uint8
	Payload   []byte
}

// Encode serialises a frame.
func Encode(f *Frame) []byte {
	buf := make([]byte, frameHeaderLen+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	flags := byte(0)
	if f.Broadcast {
		flags |= flagBroadcast
	}
	buf[4] = flags
	buf[5] = f.TTL
	binary.BigEndian.PutUint32(buf[6:10], f.PktID)
	copyIP(buf[10:26], f.Src)
	copyIP(buf[26:42], f.Dst)
	copy(buf[42:], f.Payload)
	return buf
}

// Decode parses a frame, rejecting foreign or short packets.
func Decode(b []byte) (*Frame, error) {
	if len(b) < frameHeaderLen {
		return nil, errors.New("mesh: short frame")
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return nil, errors.New("mesh: bad magic")
	}
	f := &Frame{
		Broadcast: b[4]&flagBroadcast != 0,
		TTL:       b[5],
		PktID:     binary.BigEndian.Uint32(b[6:10]),
		Src:       net.IPv4(b[10], b[11], b[12], b[13]),
		Dst:       net.IPv4(b[26], b[27], b[28], b[29]),
	}
	f.Payload = append([]byte(nil), b[42:]...)
	return f, nil
}

func copyIP(dst []byte, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		// store the v4 address at the head of the 16-byte field
		copy(dst[0:4], v4)
		return
	}
	copy(dst, ip)
}

// Link is a direct link to a peer.
type Link struct {
	PeerID    protocol.PeerID
	Vip       net.IP
	Transport string
	Send      func(payload []byte) error
}

// Node is a mesh node. It is safe for concurrent use.
type Node struct {
	ID  protocol.PeerID
	Vip net.IP
	Net *net.IPNet

	// OnData is invoked for frames delivered to this node (from the calling
	// goroutine). It must not block.
	OnData func(srcIP net.IP, payload []byte) error

	mu        sync.Mutex
	links     map[protocol.PeerID]*Link
	byIP      map[string]protocol.PeerID
	routes    map[string]protocol.PeerID // learned next hop for a virtual IP
	known     map[string]struct{}
	seen      map[seenKey]struct{}
	seenOrder []seenKey
	lastID    uint32
}

// seenKey identifies a frame for deduplication. Using a fixed-size struct
// avoids per-packet fmt/string allocation on the hot path.
type seenKey struct {
	src [4]byte
	id  uint32
}

// maxSeen bounds the mesh deduplication table. Older entries are evicted in
// FIFO order instead of clearing the whole table.
const maxSeen = 8192

// NewNode creates a node with the given virtual address and subnet.
func NewNode(id protocol.PeerID, vip net.IP, network *net.IPNet) *Node {
	return &Node{
		ID:     id,
		Vip:    vip,
		Net:    network,
		links:  make(map[protocol.PeerID]*Link),
		byIP:   make(map[string]protocol.PeerID),
		routes: make(map[string]protocol.PeerID),
		known:  make(map[string]struct{}),
		seen:   make(map[seenKey]struct{}),
	}
}

// AddLink registers or refreshes a direct link.
func (n *Node) AddLink(l *Link) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.links[l.PeerID] = l
	if l.Vip != nil {
		n.byIP[l.Vip.String()] = l.PeerID
	}
}

// RemoveLink drops a direct link.
func (n *Node) RemoveLink(peerID protocol.PeerID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if l := n.links[peerID]; l != nil && l.Vip != nil {
		if n.byIP[l.Vip.String()] == peerID {
			delete(n.byIP, l.Vip.String())
		}
	}
	for dst, next := range n.routes {
		if next == peerID {
			delete(n.routes, dst)
		}
	}
	delete(n.links, peerID)
}

// learnRoute records that srcIP is reachable via the peer we received it
// from. This lets later unicasts avoid flooding once a path has been seen.
func (n *Node) learnRoute(src net.IP, via protocol.PeerID) {
	if src == nil || via == (protocol.PeerID{}) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes[src.String()] = via
}

// AddKnownIP records a virtual address that exists in the room. Unknown
// unicast destinations are dropped instead of flooding the whole mesh.
func (n *Node) AddKnownIP(ip net.IP) {
	if ip == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.known[ip.String()] = struct{}{}
}

// RemoveKnownIP forgets a virtual address, e.g. when a member leaves.
func (n *Node) RemoveKnownIP(ip net.IP) {
	if ip == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.known, ip.String())
}

// isKnown reports whether a virtual address is a known room member. The
// caller must hold n.mu.
func (n *Node) isKnown(ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, ok := n.known[ip.String()]
	return ok
}

// SendTo routes a payload to a virtual address, flooding when no direct link
// is known.
func (n *Node) SendTo(dst net.IP, payload []byte) error {
	n.mu.Lock()
	pktID := n.nextID()
	n.mu.Unlock()
	f := &Frame{Src: n.Vip, Dst: dst, PktID: pktID, TTL: MaxTTL, Payload: payload}
	n.markSeen(f)
	return n.forward(f, protocol.PeerID{})
}

// Broadcast floods a payload to every peer.
func (n *Node) Broadcast(payload []byte) error {
	n.mu.Lock()
	pktID := n.nextID()
	bcast := n.broadcastIP()
	n.mu.Unlock()
	f := &Frame{Broadcast: true, Src: n.Vip, Dst: bcast, PktID: pktID, TTL: MaxTTL, Payload: payload}
	n.markSeen(f)
	return n.forward(f, protocol.PeerID{})
}

// Handle processes a frame received on a direct link. The origin of the
// frame (the peer it arrived from) is used to avoid echoing back.
func (n *Node) Handle(from protocol.PeerID, payload []byte) error {
	f, err := Decode(payload)
	if err != nil {
		return err
	}
	if n.duplicate(f) {
		return nil
	}
	n.markSeen(f)
	n.learnRoute(f.Src, from)

	if f.Dst != nil && f.Dst.Equal(n.Vip) {
		// unicast to us: deliver
		if n.OnData != nil {
			return n.OnData(f.Src, f.Payload)
		}
		return nil
	}

	toBroadcast := f.Broadcast || n.isBroadcast(f.Dst)
	if toBroadcast {
		// broadcast/multicast: deliver locally and forward
		if n.OnData != nil {
			n.OnData(f.Src, f.Payload)
		}
	}
	if f.TTL <= 1 {
		return nil
	}
	f.TTL--
	return n.forward(f, from)
}

// forward sends a frame to the right links. When from is non-zero the frame
// is not sent back on that link.
func (n *Node) forward(f *Frame, from protocol.PeerID) error {
	n.mu.Lock()
	links := n.snapshot()
	var targets []*Link
	toBroadcast := f.Broadcast || n.isBroadcast(f.Dst)
	if toBroadcast {
		for _, l := range links {
			if l.PeerID != from {
				targets = append(targets, l)
			}
		}
	} else {
		// unicast: prefer a direct link, then a learned route, then flood
		if pid, ok := n.byIP[f.Dst.String()]; ok {
			if l := n.links[pid]; l != nil && l.PeerID != from {
				targets = append(targets, l)
			} else {
				targets = n.othersExcept(from)
			}
		} else if pid, ok := n.routes[f.Dst.String()]; ok {
			if l := n.links[pid]; l != nil && l.PeerID != from {
				targets = append(targets, l)
			} else {
				targets = n.othersExcept(from)
			}
		} else if !n.isKnown(f.Dst) && !f.Dst.Equal(n.Vip) {
			// Unknown destination: flooding would only amplify traffic.
			targets = nil
		} else {
			// Known destination without a route: flood so multi-hop
			// routing can still find it.
			targets = n.othersExcept(from)
		}
	}
	n.mu.Unlock()

	encoded := Encode(f)
	for _, l := range targets {
		if l.Send != nil {
			l.Send(encoded)
		}
	}
	return nil
}

func (n *Node) snapshot() []*Link {
	out := make([]*Link, 0, len(n.links))
	for _, l := range n.links {
		out = append(out, l)
	}
	return out
}

func (n *Node) othersExcept(from protocol.PeerID) []*Link {
	var out []*Link
	for id, l := range n.links {
		if id != from {
			out = append(out, l)
		}
	}
	return out
}

// isBroadcast reports whether dst is the subnet broadcast or a multicast
// address.
func (n *Node) isBroadcast(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsMulticast() {
		return true
	}
	if n.Net != nil {
		return ip.Equal(n.broadcastIP())
	}
	return false
}

func (n *Node) broadcastIP() net.IP {
	if n.Net == nil {
		return nil
	}
	ip := make(net.IP, len(n.Net.IP))
	for i := range ip {
		ip[i] = n.Net.IP[i] | ^n.Net.Mask[i]
	}
	return ip.To4()
}

func (n *Node) duplicate(f *Frame) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.seen[n.seenKey(f)]
	return ok
}

func (n *Node) markSeen(f *Frame) {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := n.seenKey(f)
	if _, ok := n.seen[key]; ok {
		return
	}
	n.seen[key] = struct{}{}
	n.seenOrder = append(n.seenOrder, key)
	if len(n.seenOrder) > maxSeen {
		old := n.seenOrder[0]
		n.seenOrder = n.seenOrder[1:]
		delete(n.seen, old)
	}
}

func (n *Node) seenKey(f *Frame) seenKey {
	var k seenKey
	if v4 := f.Src.To4(); v4 != nil {
		copy(k.src[:], v4)
	}
	k.id = f.PktID
	return k
}

func (n *Node) nextID() uint32 {
	n.lastID++
	if n.lastID == 0 {
		n.lastID = 1
	}
	return n.lastID
}
