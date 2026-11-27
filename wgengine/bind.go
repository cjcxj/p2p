// Package wgengine runs a WireGuard tunnel on top of the socket that
// core/punch has already hole-punched, so discovery and tunnel traffic share a
// single NAT mapping.
package wgengine

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// maxPacket bounds the transit buffer for a WireGuard datagram. WireGuard
// messages never exceed device.MaxMessageSize, well under 64 KiB.
const maxPacket = 65536

// rxQueueSize bounds how many inbound WireGuard datagrams may wait for the
// device's receive goroutine. Overflow packets are dropped rather than
// blocking the punch read loop.
const rxQueueSize = 512

// A handshake initiation that arrives before its peer is configured is dropped
// by wireguard-go, and WireGuard then stays silent for five seconds before
// retrying. Caching the most recent initiation per endpoint lets AddPeer replay
// it, which is the difference between a tunnel that comes up at once and one that
// waits a round for nothing.
const (
	initCacheMax = 32
	initCacheTTL = 5 * time.Second
	// initSize is the fixed wire length of a Handshake Initiation message.
	initSize = 148
)

type cachedInit struct {
	pkt []byte
	at  time.Time
}

type ingress struct {
	buf  []byte
	n    int
	from netip.AddrPort
}

// endpoint is the conn.Endpoint view of a peer's UDP address. It mirrors
// conn.StdNetEndpoint so WireGuard's roaming and cookie logic behave the same.
type endpoint struct {
	netip.AddrPort
	src []byte
}

var _ conn.Endpoint = (*endpoint)(nil)

func (e *endpoint) ClearSrc() {
	if e.src != nil {
		e.src = e.src[:0]
	}
}

func (e *endpoint) SrcToString() string { return "" }

func (e *endpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (e *endpoint) DstIP() netip.Addr { return e.AddrPort.Addr() }

func (e *endpoint) DstToString() string { return e.AddrPort.String() }

func (e *endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

// Bind adapts an already-connected UDP socket to WireGuard's conn.Bind. The
// socket stays owned by the punch engine, which feeds WireGuard datagrams in
// through Ingest after separating them from its own packets.
type Bind struct {
	pc net.PacketConn

	// sender, when set, overrides how an outbound datagram reaches its
	// destination. The session installs one that writes through the punch
	// engine's *winning* socket for that peer, because a hole-punched NAT
	// mapping only exists on the socket that actually punched -- sending a
	// reply out a different socket would use an unmapped source the peer drops.
	// Nil means send straight through pc.
	sender func([]byte, *net.UDPAddr) error

	pool sync.Pool

	mu        sync.Mutex
	open      bool
	closeCh   chan struct{}
	rx        chan ingress
	localPort uint16
	// recentInit holds handshake initiations awaiting a peer to answer them.
	recentInit map[netip.AddrPort]cachedInit
}

var _ conn.Bind = (*Bind)(nil)

// NewBind wraps pc, the UDP socket the punch engine reads from.
func NewBind(pc net.PacketConn) *Bind {
	b := &Bind{
		pc:      pc,
		closeCh: make(chan struct{}),
		rx:      make(chan ingress, rxQueueSize),
		// Allocated up front: cacheInit is reached from the receive path and a nil
		// map there would panic.
		recentInit: make(map[netip.AddrPort]cachedInit, initCacheMax),
	}
	b.pool.New = func() any {
		buf := make([]byte, maxPacket)
		return &buf
	}
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		b.localPort = uint16(ua.Port)
	}
	return b
}

// SetSender installs the outbound router described on the Bind.sender field. A
// nil sender restores writing through pc directly.
func (b *Bind) SetSender(fn func([]byte, *net.UDPAddr) error) {
	b.mu.Lock()
	b.sender = fn
	b.mu.Unlock()
}

// Ingest hands a received WireGuard datagram to the device. It never blocks:
// when the device cannot keep up the packet is dropped, which WireGuard treats
// as ordinary loss.
func (b *Bind) Ingest(pkt []byte, from *net.UDPAddr) {
	ap, ok := addrPortOf(from)
	if !ok {
		return
	}
	// Type 1 is a Handshake Initiation. Cache it: the peer entry it is meant for
	// may not exist yet, and dropping it costs a five second retry.
	if len(pkt) == initSize && pkt[0] == 1 {
		b.cacheInit(ap, pkt)
	}
	ptr := b.pool.Get().(*[]byte)
	n := copy(*ptr, pkt)
	select {
	case b.rx <- ingress{buf: *ptr, n: n, from: ap}:
	default:
		b.pool.Put(ptr)
	}
}

// addrPortOf converts a receive address, IPv4 or IPv6. Accepting only IPv4 here
// silently discarded every IPv6 peer.
func addrPortOf(from *net.UDPAddr) (netip.AddrPort, bool) {
	if from == nil || len(from.IP) == 0 {
		return netip.AddrPort{}, false
	}
	var addr netip.Addr
	var ok bool
	if ip4 := from.IP.To4(); ip4 != nil {
		addr, ok = netip.AddrFromSlice(ip4)
	} else {
		addr, ok = netip.AddrFromSlice(from.IP.To16())
	}
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(from.Port)), true
}

func (b *Bind) cacheInit(ap netip.AddrPort, pkt []byte) {
	cp := append([]byte(nil), pkt...)
	now := time.Now()
	b.mu.Lock()
	if b.recentInit == nil {
		b.recentInit = make(map[netip.AddrPort]cachedInit, initCacheMax)
	}
	if len(b.recentInit) >= initCacheMax {
		// Drop the expired ones first, then the oldest, so hitting the cap cannot
		// throw away the fresh initiations that were just being cached to survive
		// the race this cache exists for.
		var oldestKey netip.AddrPort
		var oldest time.Time
		for k, v := range b.recentInit {
			if now.Sub(v.at) > initCacheTTL {
				delete(b.recentInit, k)
				continue
			}
			if oldestKey == (netip.AddrPort{}) || v.at.Before(oldest) {
				oldestKey, oldest = k, v.at
			}
		}
		if len(b.recentInit) >= initCacheMax && oldestKey != (netip.AddrPort{}) {
			delete(b.recentInit, oldestKey)
		}
	}
	b.recentInit[ap] = cachedInit{pkt: cp, at: now}
	b.mu.Unlock()
}

// ReplayInitiation feeds back a cached handshake initiation from endpointStr, if
// it is still fresh. Called once a peer has been configured, so an initiator that
// ran slightly ahead of us gets an answer immediately instead of after a retry.
func (b *Bind) ReplayInitiation(endpointStr string) {
	ap, err := netip.ParseAddrPort(endpointStr)
	if err != nil {
		return
	}
	now := time.Now()
	b.mu.Lock()
	c, ok := b.recentInit[ap]
	if ok {
		delete(b.recentInit, ap)
	}
	b.mu.Unlock()
	if !ok || now.Sub(c.at) > initCacheTTL {
		return
	}
	ptr := b.pool.Get().(*[]byte)
	n := copy(*ptr, c.pkt)
	select {
	case b.rx <- ingress{buf: *ptr, n: n, from: ap}:
	default:
		b.pool.Put(ptr)
	}
}

// ForgetInitiation discards a cached initiation for endpointStr: a peer that was
// removed, or whose initiation the device already consumed, must not be handed a
// replay whose anti-replay state is already used up.
func (b *Bind) ForgetInitiation(endpointStr string) {
	ap, err := netip.ParseAddrPort(endpointStr)
	if err != nil {
		return
	}
	b.forgetInit(ap)
}

func (b *Bind) forgetInit(ap netip.AddrPort) {
	b.mu.Lock()
	if b.recentInit != nil {
		delete(b.recentInit, ap)
	}
	b.mu.Unlock()
}

func (b *Bind) forgetInitAddr(from *net.UDPAddr) {
	if ap, ok := addrPortOf(from); ok {
		b.forgetInit(ap)
	}
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.open {
		b.mu.Unlock()
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true
	b.mu.Unlock()
	if port != 0 {
		b.localPort = port
	}
	return []conn.ReceiveFunc{b.receive}, b.localPort, nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	b.open = false
	select {
	case <-b.closeCh:
	default:
		close(b.closeCh)
	}
	return nil
}

func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) BatchSize() int { return 1 }

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &endpoint{AddrPort: ap}, nil
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	target, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	addr := net.UDPAddrFromAddrPort(target.AddrPort)
	b.mu.Lock()
	sender := b.sender
	b.mu.Unlock()
	for _, buf := range bufs {
		// A Handshake Response (type 2) leaving for this endpoint means the cached
		// initiation has been consumed; replaying it later would only collide.
		if len(buf) >= 4 && buf[0] == 2 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 {
			b.forgetInitAddr(addr)
		}
		if sender != nil {
			if err := sender(buf, addr); err != nil {
				return err
			}
			continue
		}
		if _, err := b.pc.WriteTo(buf, addr); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-b.closeCh:
		return 0, net.ErrClosed
	case in := <-b.rx:
		sizes[0] = in.n
		copy(bufs[0], in.buf[:in.n])
		eps[0] = &endpoint{AddrPort: in.from}
		b.pool.Put(&in.buf)
		return 1, nil
	}
}
