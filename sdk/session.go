package p2p

import (
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"p2p/core/mesh"
	"p2p/core/netstack"
	"p2p/core/protocol"
	"p2p/core/punch"
	"p2p/core/signaling"
	"p2p/core/stun"
	"p2p/core/tundev"
	"p2p/wgengine"
)

var errBadIP = errors.New("p2p: invalid ip address")

// udpSocketBufferSize is the target UDP socket buffer size used by Session.
// 4 MiB is a reasonable high-BDP default; OS limits may cap the actual value.
const udpSocketBufferSize = 4 << 20

// Member describes a node in the virtual network.
type Member struct {
	PeerID        string
	VirtualIP     string
	NATType       string
	Transport     string
	Endpoint      string // actual remote UDP endpoint (IP:port) when connected
	Connected     bool
	BytesSent     uint64
	BytesReceived uint64
}

// Session connects this peer to a room and the virtual network within it.
type Session struct {
	cfg Config
	l   Listener

	conn       net.PacketConn
	extraConns []*net.UDPConn // spray pool; closed in Close
	det        *stun.Detection
	id         protocol.PeerID
	vip        net.IP
	ipnet      *net.IPNet
	sig        *signaling.Client
	ph         *punch.Punch
	mesh       *mesh.Node
	room       string

	relayAddr *net.UDPAddr

	x25519     *ecdh.PrivateKey
	protector  SocketProtector
	localStack *netstack.LocalStack

	tunnel     *wgengine.Tunnel
	tunnelName string

	tunFile      *os.File
	tunWriteMu   sync.Mutex
	tunWriteCh   chan []byte
	tunWriteStop chan struct{}

	mu     sync.Mutex
	peers  map[string]*remote
	closed bool
	done   chan struct{}
	once   sync.Once
}

type remote struct {
	id            protocol.PeerID
	vip           net.IP
	connected     bool
	transport     string
	endpoint      string // actual remote UDP endpoint (IP:port)
	key           []byte // per-pair data-plane AEAD key; nil means plaintext fallback
	wgPub         string // peer's X25519 key, hex, as advertised in signaling
	wgEndpoint    string // endpoint the WireGuard peer entry was configured for
	bytesSent     uint64
	bytesReceived uint64
}

// SocketProtector protects the session's UDP socket from being routed back
// through a VPN tunnel (Android VpnService integration). Implementations
// call VpnService.protect(fd) and return whether it succeeded.
type SocketProtector interface {
	Protect(fd int) bool
}

// SetSocketProtector installs a protector for the session's UDP socket and
// applies it immediately. Call before Connect when a VPN may route the
// socket's traffic.
func (s *Session) SetSocketProtector(p SocketProtector) {
	s.mu.Lock()
	s.protector = p
	extras := s.extraConns
	s.mu.Unlock()
	protectConn(s.conn, p)
	for _, c := range extras {
		protectConn(c, p)
	}
}

func protectConn(conn net.PacketConn, p SocketProtector) {
	if p == nil {
		return
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) { p.Protect(int(fd)) })
}

// AttachTUN attaches a raw TUN file descriptor (e.g. Android VpnService) and
// runs the tunnel in Go. The session takes ownership of fd: once this call
// returns -- success or failure -- the descriptor is closed and the caller must
// not close it again. That is what lets a mobile app skip the per-packet
// Java/JNI bridge, which was the slowest part of the old data plane.
//
// By default the descriptor is handed to a WireGuard interface that reads and
// writes it directly. With Config.LegacyMesh it is bridged through the retired
// mesh data plane instead, which is how IP traffic travelled before the
// tunnel existed.
func (s *Session) AttachTUN(fd int, mtu int) error {
	if fd < 0 {
		return errors.New("p2p: invalid tun fd")
	}
	s.mu.Lock()
	legacy := s.cfg.LegacyMesh
	attached := s.tunFile != nil || s.tunnel != nil
	closed := s.closed
	s.mu.Unlock()
	if attached {
		tundev.CloseFD(fd)
		return errors.New("p2p: tun already attached")
	}
	if closed {
		tundev.CloseFD(fd)
		return net.ErrClosed
	}
	if !legacy {
		dev, err := tundev.FromFD(fd, mtu)
		if err != nil {
			return err
		}
		return s.startTunnel(dev.TUN(), dev.Name())
	}
	f := os.NewFile(uintptr(fd), "p2p-tun")
	if f == nil {
		return errors.New("p2p: invalid tun fd")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		f.Close()
		return net.ErrClosed
	}
	if s.tunFile != nil {
		s.mu.Unlock()
		f.Close()
		return errors.New("p2p: tun already attached")
	}
	writeCh := make(chan []byte, 4096)
	writeStop := make(chan struct{})
	s.tunFile = f
	s.tunWriteCh = writeCh
	s.tunWriteStop = writeStop
	s.mu.Unlock()
	if mtu <= 0 {
		mtu = 1280
	}
	go s.tunWriteWorker(f, writeCh, writeStop)
	go s.tunReadLoop(f, mtu)
	return nil
}

func (s *Session) tunWriteWorker(f *os.File, ch <-chan []byte, stop <-chan struct{}) {
	for {
		select {
		case pkt := <-ch:
			s.tunWriteMu.Lock()
			_, _ = f.Write(pkt)
			s.tunWriteMu.Unlock()
		case <-stop:
			return
		}
	}
}

func (s *Session) tunReadLoop(f *os.File, mtu int) {
	buf := make([]byte, mtu+256)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			pkt := buf[:n]
			dst := ipv4Dst(pkt)
			if dst == nil {
				continue
			}
			if dst.IsMulticast() || dst.Equal(net.IPv4bcast) || dst.IsUnspecified() {
				_ = s.Broadcast(pkt)
			} else {
				_ = s.SendToIP(dst.String(), pkt)
			}
		}
		if err != nil {
			return
		}
	}
}

// EnableLocalStack creates a userspace IP endpoint for this node's virtual
// address. Inbound IP packets addressed to the local virtual IP are then
// handled in-process (e.g. ICMP echo replies) instead of being delivered as
// EventData -- required on platforms where the kernel cannot route replies
// back through a VPN tun (Android). Call after Connect once LocalIP is set.
func (s *Session) EnableLocalStack() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.localStack != nil {
		return nil
	}
	if s.vip == nil || s.ipnet == nil {
		return errors.New("p2p: session not ready (no virtual address)")
	}
	ls, err := netstack.NewLocalStack(s.vip, s.ipnet, func(ipPkt []byte) {
		if d := ipv4Dst(ipPkt); d != nil {
			_ = s.SendToIP(d.String(), ipPkt)
		}
	})
	if err != nil {
		return err
	}
	s.localStack = ls
	return nil
}

// ExposeTCP makes this device's virtual address accept TCP connections on
// port and forwards them to 127.0.0.1:port locally, so other nodes can reach
// TCP services running on this device through the virtual IP. Requires
// EnableLocalStack.
func (s *Session) ExposeTCP(port int) error {
	s.mu.Lock()
	ls := s.localStack
	s.mu.Unlock()
	if ls == nil {
		return errors.New("p2p: local stack not enabled (call EnableLocalStack first)")
	}
	return ls.ExposeTCP(uint16(port))
}

// ipv4Dst returns the destination IPv4 of a raw IP packet, or nil.
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

// newPrimaryConn creates the session's main UDP socket. When the block spray
// is active it binds the socket to the block base (StepProbePort) so the
// public port advertised to peers is the base of the contiguous local block;
// the peer's aim at advertised+offset then lands on pool socket `offset`.
// Falls back to an ephemeral port if the base is unavailable.
func newPrimaryConn(cfg *Config) (*net.UDPConn, error) {
	if cfg.PredictionSockets > 1 {
		if c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: stun.StepProbePort}); err == nil {
			return c, nil
		}
	}
	return net.ListenUDP("udp4", nil)
}

// NewSession creates a session over a fresh UDP socket.
func NewSession(cfg *Config, l Listener) (*Session, error) {
	if cfg == nil {
		cfg = Defaults()
	}
	cfg.applyDefaults()
	if l == nil {
		l = nullListener{}
	}
	conn, err := newPrimaryConn(cfg)
	if err != nil {
		return nil, err
	}
	// High-latency WAN paths need large UDP socket buffers; the OS defaults are
	// often far too small for mesh throughput over mobile/home NAT links.
	_ = conn.SetReadBuffer(udpSocketBufferSize)
	_ = conn.SetWriteBuffer(udpSocketBufferSize)
	key, err := newDataKey()
	if err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{cfg: *cfg, l: l, conn: conn, peers: make(map[string]*remote), x25519: key}
	return s, nil
}

type nullListener struct{}

func (nullListener) OnEvent(int, string, []byte) {}

// LocalID returns this peer's identifier (valid after Connect).
func (s *Session) LocalID() string {
	return s.id.String()
}

// LocalIP returns this peer's virtual address (valid after Connect).
func (s *Session) LocalIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vip == nil {
		return ""
	}
	return s.vip.String()
}

// Subnet returns the room's virtual subnet (e.g. "10.9.0.0/24").
func (s *Session) Subnet() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipnet == nil {
		return ""
	}
	return s.ipnet.String()
}

// NATType returns the detected NAT type (valid after Connect).
func (s *Session) NATType() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.det == nil {
		return string(stun.NatUnknown)
	}
	return string(s.det.NATType)
}

// Members lists the known nodes of the virtual network.
func (s *Session) Members() []*Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.memberList()
}

// MemberCount returns the number of known nodes (mobile-friendly accessor).
func (s *Session) MemberCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peers)
}

// MemberAt returns the i-th known node (mobile-friendly accessor).
func (s *Session) MemberAt(i int) *Member {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.memberList()
	if i < 0 || i >= len(list) {
		return nil
	}
	return list[i]
}

func (s *Session) memberList() []*Member {
	out := make([]*Member, 0, len(s.peers))
	for _, r := range s.peers {
		m := &Member{PeerID: r.id.String(), Connected: r.connected, Transport: r.transport, Endpoint: r.endpoint, BytesSent: r.bytesSent, BytesReceived: r.bytesReceived}
		if r.vip != nil {
			m.VirtualIP = r.vip.String()
		}
		out = append(out, m)
	}
	return out
}

// Connect joins a room and begins the connection pipeline asynchronously.
func (s *Session) Connect(room string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.done != nil {
		s.mu.Unlock()
		return nil
	}
	s.done = make(chan struct{})
	s.room = room
	s.mu.Unlock()

	go s.run(room)
	return nil
}

// SendToIP routes a payload to a virtual address, possibly via intermediate
// nodes.
func (s *Session) SendToIP(dstIP string, data []byte) error {
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return errBadIP
	}
	return s.sendToMesh(ip, data)
}

// Broadcast sends a payload to every node in the room.
func (s *Session) Broadcast(data []byte) error {
	s.mu.Lock()
	m := s.mesh
	s.mu.Unlock()
	if m == nil {
		return net.ErrClosed
	}
	return m.Broadcast(data)
}

// Send delivers a payload to a peer (by peer id or virtual address), routed
// through the mesh.
func (s *Session) Send(peerID string, data []byte) error {
	s.mu.Lock()
	r := s.peers[peerID]
	if r == nil {
		if ip := net.ParseIP(peerID); ip != nil {
			for _, rr := range s.peers {
				if rr.vip != nil && rr.vip.Equal(ip) {
					r = rr
					break
				}
			}
		}
	}
	var vip net.IP
	if r != nil {
		vip = r.vip
	}
	s.mu.Unlock()
	if r == nil || vip == nil {
		return errors.New("p2p: no route to peer")
	}
	return s.sendToMesh(vip, data)
}

// sendSecure sends a mesh payload to a peer, encrypting it with the per-pair
// data-plane key when one has been negotiated. Without a key it falls back to
// the historical plaintext path for compatibility with older peers.
func (s *Session) sendSecure(id protocol.PeerID, payload []byte) error {
	s.mu.Lock()
	r := s.peers[id.String()]
	ph := s.ph
	var key []byte
	if r != nil {
		r.bytesSent += uint64(len(payload))
		if len(r.key) > 0 {
			key = append([]byte(nil), r.key...)
		}
	}
	s.mu.Unlock()
	if ph == nil {
		return net.ErrClosed
	}
	if len(key) > 0 && !s.cfg.Plaintext {
		sealed, err := sealData(key, payload)
		if err != nil {
			return err
		}
		payload = sealed
	}
	return ph.Send(id, payload)
}

// sendToMesh sends an application payload to a virtual IP. When a per-pair
// key with the final destination is available, the payload is encrypted
// end-to-end before entering the mesh, so intermediate nodes cannot read it.
func (s *Session) sendToMesh(dst net.IP, data []byte) error {
	s.mu.Lock()
	m := s.mesh
	var key []byte
	for _, r := range s.peers {
		if r.vip != nil && r.vip.Equal(dst) && len(r.key) > 0 {
			key = append([]byte(nil), r.key...)
			break
		}
	}
	s.mu.Unlock()
	if m == nil {
		return net.ErrClosed
	}
	if len(key) > 0 && !s.cfg.Plaintext {
		sealed, err := sealE2E(key, data)
		if err != nil {
			return err
		}
		data = sealed
	}
	return m.SendTo(dst, data)
}

// openInbound decrypts an end-to-end encrypted payload received from src.
// Broadcast and legacy plaintext payloads are returned unchanged.
func (s *Session) openInbound(src net.IP, payload []byte) []byte {
	if s.cfg.Plaintext {
		return payload
	}
	s.mu.Lock()
	var key []byte
	for _, r := range s.peers {
		if r.vip != nil && r.vip.Equal(src) && len(r.key) > 0 {
			key = append([]byte(nil), r.key...)
			break
		}
	}
	s.mu.Unlock()
	if len(key) == 0 {
		return payload
	}
	dec, marked, err := openE2E(key, payload)
	if err != nil {
		if s.cfg.Debug {
			s.emit(EventDebug, "", []byte("p2p: dropped undecryptable e2e packet from "+src.String()))
		}
		return nil
	}
	if marked {
		return dec
	}
	return payload
}

// Disconnect tears the session down. It is safe to call before Connect; in
// that case the session is simply marked closed and the socket released.
func (s *Session) Disconnect() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		done := s.done
		if done != nil {
			close(done)
		}
		sig := s.sig
		ph := s.ph
		tun := s.tunnel
		tf := s.tunFile
		ch := s.tunWriteCh
		stop := s.tunWriteStop
		extraConns := s.extraConns
		s.tunnel = nil
		s.tunnelName = ""
		s.tunFile = nil
		s.tunWriteCh = nil
		s.tunWriteStop = nil
		s.extraConns = nil
		s.mu.Unlock()
		if sig != nil {
			sig.Close()
		}
		// Stop the tunnel before the socket: its device would otherwise try to
		// write WireGuard frames onto a closed conn.
		if tun != nil {
			tun.Stop()
		}
		// close the socket first so the punch read loop unblocks
		s.conn.Close()
		for _, ec := range extraConns {
			ec.Close()
		}
		if ph != nil {
			ph.Stop()
		}
		if stop != nil {
			close(stop)
		}
		if tf != nil {
			_ = tf.Close()
		}
		_ = ch
		s.emit(EventStateChanged, "", []byte(StateClosed))
	})
}

// run is the connection pipeline.
func (s *Session) run(room string) {
	// 1. NAT detection over our UDP socket.
	det, err := s.detect()
	if err != nil {
		det = &stun.Detection{NATType: stun.NatUnknown, LocalAddr: localUDP(s.conn)}
	}
	s.mu.Lock()
	s.det = det
	s.mu.Unlock()
	// The classification decides the whole punching plan, and a wrong one is
	// invisible unless the evidence is printed: "port_restricted_cone" learned
	// from a reachable alternate destination and the same guess learned from
	// nothing look identical otherwise.
	if m := det.Method(); m != "" {
		s.debugf("p2p: NAT " + string(det.NATType) + ": " + m)
	}
	// Detection sets a read deadline on the socket; clear it so the punch
	// engine can block freely.
	if dc, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		dc.SetReadDeadline(time.Time{})
	}

	// 2. Signaling handshake (assigns our peer id and virtual address).
	var sigAuth *signaling.Auth
	if s.cfg.AuthSecret != "" {
		sigAuth = &signaling.Auth{User: s.cfg.AuthUser, Secret: s.cfg.AuthSecret}
	}
	var sig *signaling.Client
	if s.cfg.TLS {
		tlsCfg := &tls.Config{
			ServerName:         s.cfg.TLSServerName,
			InsecureSkipVerify: s.cfg.TLSInsecureSkipVerify,
		}
		sig, err = signaling.DialTLS(s.cfg.ServerAddr, room, s.cfg.Token, sigAuth, tlsCfg)
	} else {
		sig, err = signaling.Dial(s.cfg.ServerAddr, room, s.cfg.Token, sigAuth)
	}
	if err != nil {
		s.emit(EventError, "", []byte(err.Error()))
		s.emit(EventStateChanged, "", []byte(StateFailed))
		return
	}
	s.mu.Lock()
	s.id = sig.PeerID()
	if v := sig.VirtualIP(); v != "" {
		s.vip = net.ParseIP(v)
	}
	if n := sig.Network(); n != "" {
		_, s.ipnet, _ = net.ParseCIDR(n)
	}
	s.sig = sig
	s.mu.Unlock()
	s.emit(EventStateChanged, "", []byte(StateConnecting))

	// 3. Mesh node (virtual addressing + routing).
	meshNode := mesh.NewNode(s.id, s.vip, s.ipnet)
	meshNode.OnData = func(src net.IP, payload []byte) error {
		payload = s.openInbound(src, payload)
		if payload == nil {
			return nil
		}
		s.mu.Lock()
		ls := s.localStack
		s.mu.Unlock()
		if ls != nil && ls.Wants(payload) {
			// IP packet the userspace stack should answer (ICMP echo / TCP to
			// our virtual address): handled in-process, no EventData.
			ls.HandleInbound(payload)
			return nil
		}
		s.mu.Lock()
		tf := s.tunFile
		ch := s.tunWriteCh
		s.mu.Unlock()
		if tf != nil {
			if ch != nil {
				// Never block the punch read loop on a slow TUN write; drop
				// only when the write queue is full.
				select {
				case ch <- payload:
				default:
				}
			} else {
				s.tunWriteMu.Lock()
				_, _ = tf.Write(payload)
				s.tunWriteMu.Unlock()
			}
			return nil
		}
		s.emit(EventData, src.String(), payload)
		return nil
	}
	s.mu.Lock()
	s.mesh = meshNode
	s.mu.Unlock()

	// 4. Punch engine over the same UDP socket.
	// det.LocalAddr already resolves the wildcard socket address to a concrete
	// LAN IP when possible; fall back to the raw socket address only if needed.
	privateAddr := det.LocalAddr
	if privateAddr == nil {
		privateAddr = localUDP(s.conn)
	}
	my := punch.NATInfo{
		Type:        det.NATType,
		PrivateAddr: privateAddr,
	}
	if det.MappedAddr != nil {
		my.PublicAddr = det.MappedAddr
	}
	my.PortDelta = det.PortDelta
	my.PortStep = det.PortStep

	ph := punch.New(s.conn, s.id, my, punch.Config{
		PortPrediction:    s.cfg.PortPrediction,
		RelayFallback:     s.cfg.RelayEnabled,
		EnableLAN:         s.cfg.EnableLAN,
		ProbeIntervalMs:   s.cfg.ProbeIntervalMs,
		PunchTimeoutMs:    s.cfg.PunchTimeoutMs,
		PredictionSockets: s.cfg.PredictionSockets,
		PeerPortOffset:    s.cfg.PeerPortOffset,
		SymmetricSpray:    s.cfg.SymmetricSpray,
	})
	if s.cfg.Debug {
		ph.Config.OnLog = func(format string, args ...interface{}) {
			s.emit(EventDebug, "", []byte(fmt.Sprintf(format, args...)))
		}
	}
	ph.OnData = func(src protocol.PeerID, pkt *punch.Packet) error {
		payload := pkt.Payload
		s.mu.Lock()
		r := s.peers[src.String()]
		var key []byte
		if r != nil && len(r.key) > 0 {
			key = append([]byte(nil), r.key...)
		}
		s.mu.Unlock()
		if len(key) > 0 && !s.cfg.Plaintext {
			dec, err := openData(key, payload)
			if err != nil {
				// Drop undecryptable/tampered packets. They cannot be
				// routed safely.
				if s.cfg.Debug {
					s.emit(EventDebug, "", []byte("p2p: dropped undecryptable data packet from "+src.String()[:8]))
				}
				return nil
			}
			payload = dec
		}
		s.mu.Lock()
		if r := s.peers[src.String()]; r != nil {
			r.bytesReceived += uint64(len(payload))
		}
		s.mu.Unlock()
		return meshNode.Handle(src, payload)
	}
	ph.OnState = func(id protocol.PeerID, t string, endpoint string) {
		s.onPeerConnected(id, t, endpoint)
	}
	// Build the spray socket pool before starting the punch engine.
	if s.cfg.PredictionSockets > 1 {
		pool := make([]net.PacketConn, s.cfg.PredictionSockets)
		pool[0] = s.conn
		extra := make([]*net.UDPConn, 0, s.cfg.PredictionSockets-1)
		for i := 1; i < s.cfg.PredictionSockets; i++ {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: stun.StepProbePort + i})
			if err != nil {
				c, err = net.ListenUDP("udp4", nil)
				if err != nil {
					break
				}
			}
			_ = c.SetReadBuffer(udpSocketBufferSize)
			_ = c.SetWriteBuffer(udpSocketBufferSize)
			protectConn(c, s.protector)
			pool[i] = c
			extra = append(extra, c)
		}
		s.mu.Lock()
		s.extraConns = extra
		s.mu.Unlock()
		ph.Conns = pool
	}
	ph.Start()
	s.mu.Lock()
	s.ph = ph
	tun := s.tunnel
	s.mu.Unlock()
	// A tunnel attached before the punch engine existed -- possible with
	// AttachTUN, which takes a descriptor the app already owns -- has had
	// nowhere to receive its frames. Hook this socket up now.
	if tun != nil {
		wireTunnel(tun, ph)
		s.applyTunnelPeers(s.pendingTunnelPeers())
	}

	sig.OnMessage = func(m protocol.Message) error {
		return s.onSignaling(m)
	}
	sig.OnClose = func(err error) {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
		s.emit(EventError, "", []byte("signaling: connection closed ("+err.Error()+"); existing p2p links remain active"))
	}
	go sig.Run()

	// Session is now fully connected to the room: signaling is running,
	// the mesh node exists and the punch engine is listening.
	s.emit(EventStateChanged, "", []byte(StateConnected))

	// Timeout watchdog: after TimeoutSec, wait a grace period for late
	// joiners before reporting an empty/unreachable room.
	go func() {
		sec := s.cfg.TimeoutSec
		select {
		case <-time.After(time.Duration(sec) * time.Second):
			select {
			case <-s.done:
				return
			case <-time.After(5 * time.Second):
			}
			s.mu.Lock()
			peerCount := len(s.peers)
			anyConnected := false
			for _, r := range s.peers {
				if r.connected {
					anyConnected = true
					break
				}
			}
			s.mu.Unlock()
			if !anyConnected {
				if peerCount == 0 {
					s.emit(EventError, "", []byte("房间内暂无其他节点：请在其他设备用相同房间名启动客户端"))
				} else {
					s.emit(EventError, "", []byte("connect timeout: peers in room not reachable"))
				}
			}
		case <-s.done:
		}
	}()
}

func (s *Session) detect() (*stun.Detection, error) {
	server, err := net.ResolveUDPAddr("udp", s.cfg.STUNAddr)
	if err != nil {
		return nil, err
	}
	c := &stun.Client{Conn: s.conn, Server: server, Retries: 1, Timeout: 400 * time.Millisecond, StepSamples: stun.DefaultStepSamples}
	// Operator-supplied observation points override the built-in (China-carrier
	// reachable) defaults, so the CGNAT candidate discovery generalizes to the
	// deployment's own network instead of a fixed public STUN list.
	if list := splitCSV(s.cfg.STUNSecondaries); len(list) > 0 {
		c.Secondaries = list
	}
	return c.Detect()
}

// splitCSV trims a comma-separated list into non-empty tokens.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func localUDP(conn net.PacketConn) *net.UDPAddr {
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a
	}
	return nil
}

// onSignaling handles inbound signaling frames.
func (s *Session) onSignaling(m protocol.Message) error {
	switch m.Type {
	case protocol.MsgMembers:
		s.syncMembers(m.Members)
	case protocol.MsgCandidate:
		if m.Candidate == nil {
			return nil
		}
		s.onPeerCandidate(m)
	case protocol.MsgRelayGrant:
		// Single-port server: TCP signaling, UDP STUN and UDP relay all share
		// the same host:port. If the server omits --public it may advertise a
		// loopback/unspecified relay address; in that case use the address the
		// client actually used to reach the server.
		relayAddrStr := s.cfg.ServerAddr
		if m.RelayAddr != "" {
			if host, _, err := net.SplitHostPort(m.RelayAddr); err == nil {
				ip := net.ParseIP(host)
				if ip == nil || (!ip.IsLoopback() && !ip.IsUnspecified()) {
					relayAddrStr = m.RelayAddr
				}
			}
		}
		addr, err := net.ResolveUDPAddr("udp", relayAddrStr)
		if err == nil {
			tok := m.RelayToken
			if tok == "" {
				tok = s.cfg.Token // older servers: fall back to room token
			}
			s.mu.Lock()
			s.relayAddr = addr
			ph := s.ph
			room := s.room
			s.mu.Unlock()
			if ph != nil {
				ph.RegisterRelay(addr, room, tok)
			}
		}
	case protocol.MsgError:
		s.emit(EventError, "", []byte(m.Error))
	}
	return nil
}

// syncMembers reconciles the room membership from the full member list.
func (s *Session) syncMembers(list []protocol.MemberInfo) {
	seen := make(map[string]bool, len(list))
	for _, mi := range list {
		if mi.PeerID == s.id.String() {
			continue // never treat ourselves as a peer
		}
		seen[mi.PeerID] = true
		ip := net.ParseIP(mi.VirtualIP)
		s.mu.Lock()
		meshNode := s.mesh
		r, ok := s.peers[mi.PeerID]
		if !ok {
			r = &remote{}
			if id, err := protocol.ParsePeerID(mi.PeerID); err == nil {
				r.id = id
			}
			s.peers[mi.PeerID] = r
		}
		if ip != nil {
			r.vip = ip
		}
		s.mu.Unlock()
		if meshNode != nil && ip != nil {
			meshNode.AddKnownIP(ip)
		}
		if !ok {
			s.onNewPeer(mi.PeerID)
		}
	}
	// leave detection
	s.mu.Lock()
	var gone []string
	for id := range s.peers {
		if !seen[id] {
			gone = append(gone, id)
		}
	}
	s.mu.Unlock()
	for _, id := range gone {
		s.onPeerLeave(id)
	}
}

// onNewPeer starts the candidate exchange with a newly discovered node.
func (s *Session) onNewPeer(idStr string) {
	s.mu.Lock()
	r := s.peers[idStr]
	vip := ""
	if r != nil && r.vip != nil {
		vip = r.vip.String()
	}
	s.mu.Unlock()

	s.emit(EventPeerJoined, vip, []byte(idStr))
	// send our candidate to them
	cand := s.buildCandidate()
	c := *cand
	c.PeerID = idStr
	s.sig.Send(protocol.Message{
		Type:      protocol.MsgCandidate,
		PeerID:    s.id.String(),
		Candidate: &c,
	})
}

// onPeerCandidate feeds a received candidate into the punch engine and, when
// both sides advertise X25519 keys, derives the per-pair data-plane AEAD key.
func (s *Session) onPeerCandidate(m protocol.Message) {
	sender := m.PeerID
	if sender == "" || sender == s.id.String() {
		return
	}
	senderID, err := protocol.ParsePeerID(sender)
	if err != nil {
		return
	}
	c := m.Candidate
	info, err := candidateToNAT(c)
	if err != nil {
		return
	}
	key := s.negotiateDataKey(senderID, c.X25519Pub)
	s.mu.Lock()
	if s.relayAddr != nil && info.RelayAddr == nil {
		info.RelayAddr = s.relayAddr
	}
	// record the peer's virtual address and negotiated key
	r := s.peers[sender]
	if r == nil {
		r = &remote{id: senderID}
		s.peers[sender] = r
	}
	r.id = senderID
	var vipIP net.IP
	if ip := net.ParseIP(c.VirtualIP); ip != nil {
		r.vip = ip
		vipIP = ip
	}
	if key != nil {
		r.key = key
	}
	if c.X25519Pub != "" {
		r.wgPub = c.X25519Pub
	}
	// A candidate can also arrive after the link was already punched, with a
	// better endpoint than the one the tunnel is using.
	tp, needTunnel := s.tunnelPeer(sender, r)
	meshNode := s.mesh
	ph := s.ph
	s.mu.Unlock()
	if meshNode != nil && vipIP != nil {
		meshNode.AddKnownIP(vipIP)
	}
	if ph == nil {
		return
	}
	// Actionable diagnostic for the one case that can still defeat a symmetric
	// peer: its candidate set enumerates only one public IP. If that IP is not
	// the address it uses toward us (a destination-rotating CGNAT), the spray
	// has nothing correct to aim at. Rather than fail silently onto the relay,
	// surface the fix: configure more STUN observation points.
	if s.cfg.Debug && info.Type == stun.NatSymmetric && len(info.CandidateIPs()) <= 1 {
		s.debugf("p2p: peer " + sender + " is symmetric but exposes a single candidate IP; " +
			"if punching falls back to relay, add more --stun-list observation points so its egress pool is enumerated")
	}
	ph.AddPeer(senderID, info)
	if needTunnel {
		s.applyTunnelPeers([]tunnelPeer{tp})
	}
}

func (s *Session) onPeerConnected(id protocol.PeerID, transport, endpoint string) {
	if id == s.id {
		return
	}
	s.mu.Lock()
	r, ok := s.peers[id.String()]
	if !ok {
		r = &remote{id: id}
		s.peers[id.String()] = r
	}
	first := !r.connected
	oldTransport := r.transport
	r.connected = true
	r.transport = transport
	r.endpoint = endpoint
	idStr := id.String()
	// A link that fell back to relay no longer carries raw WireGuard frames:
	// the relay only forwards the punch engine's own framing.
	var gonePub, goneEndpoint string
	if transport == TransportRelay && r.wgEndpoint != "" {
		gonePub, goneEndpoint = r.wgPub, r.wgEndpoint
		r.wgEndpoint = ""
	}
	tp, needTunnel := s.tunnelPeer(idStr, r)
	vip := ""
	var vipIP net.IP
	if r.vip != nil {
		vip = r.vip.String()
		vipIP = r.vip
	}
	meshNode := s.mesh
	ph := s.ph
	peerID := id
	s.mu.Unlock()

	// register the direct link in the mesh so it can route through it
	if meshNode != nil && ph != nil {
		meshNode.AddLink(&mesh.Link{
			PeerID:    peerID,
			Vip:       vipIP,
			Transport: transport,
			Send: func(payload []byte) error {
				return s.sendSecure(peerID, payload)
			},
		})
	}
	if first {
		s.emit(EventPeerConnected, vip, []byte(transport))
	} else if oldTransport != "" && oldTransport != transport {
		s.emit(EventPathChanged, vip, []byte(transport))
	}
	s.dropTunnelPeer(gonePub, goneEndpoint)
	if needTunnel {
		s.applyTunnelPeers([]tunnelPeer{tp})
	}
}

func (s *Session) onPeerLeave(idStr string) {
	s.mu.Lock()
	r := s.peers[idStr]
	delete(s.peers, idStr)
	meshNode := s.mesh
	ph := s.ph
	var vipIP net.IP
	var gonePub, goneEndpoint string
	if r != nil {
		gonePub, goneEndpoint = r.wgPub, r.wgEndpoint
		if r.vip != nil {
			vipIP = r.vip
		}
	}
	s.mu.Unlock()
	vip := ""
	if vipIP != nil {
		vip = vipIP.String()
		if meshNode != nil {
			meshNode.RemoveKnownIP(vipIP)
		}
	}
	if ph != nil {
		if id, err := protocol.ParsePeerID(idStr); err == nil {
			ph.RemovePeer(id)
			if meshNode != nil {
				meshNode.RemoveLink(id)
			}
		}
	}
	s.emit(EventPeerLeft, vip, []byte(idStr))
	s.dropTunnelPeer(gonePub, goneEndpoint)
}

// buildCandidate assembles this peer's punching candidate.
func (s *Session) buildCandidate() *protocol.Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	det := s.det
	c := &protocol.Candidate{
		NATType:     string(stun.NatUnknown),
		PrivateAddr: "",
		PortDelta:   0,
	}
	if s.vip != nil {
		c.VirtualIP = s.vip.String()
	}
	if det != nil {
		c.NATType = string(det.NATType)
		c.PortDelta = det.PortDelta
		c.PortStep = det.PortStep
		if det.MappedAddr != nil {
			// Smuggle the observation-point IPs (destination-rotating CGNAT)
			// into the string field the server forwards verbatim, as
			// "ip:port,ip2,ip3". A peer that understands them sprays each;
			// anything else only ever sees the first token.
			c.PublicAddr = det.MappedAddr.String()
			for _, ip := range det.ObservedIPs {
				if ip == nil || ip.Equal(det.MappedAddr.IP) {
					continue
				}
				c.PublicAddr += "," + ip.String()
			}
		}
		if det.LocalAddr != nil {
			c.PrivateAddr = det.LocalAddr.String()
		}
	}
	if s.relayAddr != nil {
		c.RelayAddr = s.relayAddr.String()
	}
	c.X25519Pub = dataPublicHex(s.x25519)
	return c
}

func candidateToNAT(c *protocol.Candidate) (punch.NATInfo, error) {
	info := punch.NATInfo{
		Type:      stun.NATType(c.NATType),
		PortDelta: c.PortDelta,
		PortStep:  c.PortStep,
	}
	var err error
	if c.PublicAddr != "" {
		// The sender may smuggle extra observation-point IPs after the primary
		// address as a comma list, carried in this string field so an older
		// signaling server that forwards Candidate verbatim still delivers
		// them. First token is the primary ip:port; the rest are bare IPs.
		primary, extras := splitCandidateAddr(c.PublicAddr)
		if info.PublicAddr, err = net.ResolveUDPAddr("udp", primary); err != nil {
			return info, err
		}
		for _, e := range extras {
			if ip := net.ParseIP(e); ip != nil {
				info.PublicIPs = append(info.PublicIPs, ip)
			}
		}
	}
	if c.PrivateAddr != "" {
		if info.PrivateAddr, err = net.ResolveUDPAddr("udp", c.PrivateAddr); err != nil {
			return info, err
		}
	}
	if c.RelayAddr != "" {
		if info.RelayAddr, err = net.ResolveUDPAddr("udp", c.RelayAddr); err != nil {
			return info, err
		}
	}
	return info, nil
}

// splitCandidateAddr separates a candidate public address ("ip:port" optionally
// followed by ",ip2,ip3" observation-point extras) into its primary token and
// the extra bare-IP tokens.
func splitCandidateAddr(s string) (string, []string) {
	idx := strings.IndexByte(s, ',')
	if idx < 0 {
		return s, nil
	}
	head := s[:idx]
	var extras []string
	for _, part := range strings.Split(s[idx+1:], ",") {
		if part != "" {
			extras = append(extras, part)
		}
	}
	return head, extras
}

// emit dispatches an event to the listener.
func (s *Session) emit(event int, peerID string, data []byte) {
	s.l.OnEvent(event, peerID, data)
}

// debugf reports an internal failure only when verbose flow logging is on.
func (s *Session) debugf(msg string) {
	if s.cfg.Debug {
		s.emit(EventDebug, "", []byte(msg))
	}
}
