package p2p

import (
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"p2p/core/mesh"
	"p2p/core/netstack"
	"p2p/core/protocol"
	"p2p/core/punch"
	"p2p/core/signaling"
	"p2p/core/stun"
)

var errBadIP = errors.New("p2p: invalid ip address")

// Member describes a node in the virtual network.
type Member struct {
	PeerID        string
	VirtualIP     string
	NATType       string
	Transport     string
	Connected     bool
	BytesSent     uint64
	BytesReceived uint64
}

// Session connects this peer to a room and the virtual network within it.
type Session struct {
	cfg Config
	l   Listener

	conn  net.PacketConn
	det   *stun.Detection
	id    protocol.PeerID
	vip   net.IP
	ipnet *net.IPNet
	sig   *signaling.Client
	ph    *punch.Punch
	mesh  *mesh.Node
	room  string

	relayAddr *net.UDPAddr

	x25519     *ecdh.PrivateKey
	protector  SocketProtector
	localStack *netstack.LocalStack

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
	key           []byte // per-pair data-plane AEAD key; nil means plaintext fallback
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
	s.mu.Unlock()
	protectConn(s.conn, p)
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

// NewSession creates a session over a fresh UDP socket.
func NewSession(cfg *Config, l Listener) (*Session, error) {
	if cfg == nil {
		cfg = Defaults()
	}
	cfg.applyDefaults()
	if l == nil {
		l = nullListener{}
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
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
		m := &Member{PeerID: r.id.String(), Connected: r.connected, Transport: r.transport, BytesSent: r.bytesSent, BytesReceived: r.bytesReceived}
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
	s.mu.Lock()
	m := s.mesh
	s.mu.Unlock()
	if m == nil {
		return net.ErrClosed
	}
	return m.SendTo(ip, data)
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
	m := s.mesh
	s.mu.Unlock()
	if r == nil || r.vip == nil || m == nil {
		return errors.New("p2p: no route to peer")
	}
	return m.SendTo(r.vip, data)
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
	if len(key) > 0 {
		sealed, err := sealData(key, payload)
		if err != nil {
			return err
		}
		payload = sealed
	}
	return ph.Send(id, payload)
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
		s.mu.Unlock()
		if sig != nil {
			sig.Close()
		}
		// close the socket first so the punch read loop unblocks
		s.conn.Close()
		if ph != nil {
			ph.Stop()
		}
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
		s.mu.Lock()
		ls := s.localStack
		s.mu.Unlock()
		if ls != nil && ls.Wants(payload) {
			// IP packet the userspace stack should answer (ICMP echo / TCP to
			// our virtual address): handled in-process, no EventData.
			ls.HandleInbound(payload)
			return nil
		}
		s.emit(EventData, src.String(), payload)
		return nil
	}
	s.mu.Lock()
	s.mesh = meshNode
	s.mu.Unlock()

	// 4. Punch engine over the same UDP socket.
	my := punch.NATInfo{
		Type:        det.NATType,
		PrivateAddr: localUDP(s.conn),
	}
	if det.MappedAddr != nil {
		my.PublicAddr = det.MappedAddr
	}
	my.PortDelta = det.PortDelta

	ph := punch.New(s.conn, s.id, my, punch.Config{
		PortPrediction:  s.cfg.PortPrediction,
		RelayFallback:   s.cfg.RelayEnabled,
		EnableLAN:       s.cfg.EnableLAN,
		ProbeIntervalMs: s.cfg.ProbeIntervalMs,
		PunchTimeoutMs:  s.cfg.PunchTimeoutMs,
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
		if len(key) > 0 {
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
	ph.OnState = func(id protocol.PeerID, t string) {
		s.onPeerConnected(id, t)
	}
	ph.Start()
	s.mu.Lock()
	s.ph = ph
	s.mu.Unlock()

	sig.OnMessage = func(m protocol.Message) error {
		return s.onSignaling(m)
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
	c := &stun.Client{Conn: s.conn, Server: server, Retries: 1, Timeout: 400 * time.Millisecond}
	return c.Detect()
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
		addr, err := net.ResolveUDPAddr("udp", m.RelayAddr)
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
	var vipIP net.IP
	if ip := net.ParseIP(c.VirtualIP); ip != nil {
		r.vip = ip
		vipIP = ip
	}
	if key != nil {
		r.key = key
	}
	meshNode := s.mesh
	ph := s.ph
	s.mu.Unlock()
	if meshNode != nil && vipIP != nil {
		meshNode.AddKnownIP(vipIP)
	}
	if ph == nil {
		return
	}
	ph.AddPeer(senderID, info)
}

func (s *Session) onPeerConnected(id protocol.PeerID, transport string) {
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
}

func (s *Session) onPeerLeave(idStr string) {
	s.mu.Lock()
	r := s.peers[idStr]
	delete(s.peers, idStr)
	meshNode := s.mesh
	ph := s.ph
	var vipIP net.IP
	if r != nil && r.vip != nil {
		vipIP = r.vip
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
		if det.MappedAddr != nil {
			c.PublicAddr = det.MappedAddr.String()
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
	}
	var err error
	if c.PublicAddr != "" {
		if info.PublicAddr, err = net.ResolveUDPAddr("udp", c.PublicAddr); err != nil {
			return info, err
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

// emit dispatches an event to the listener.
func (s *Session) emit(event int, peerID string, data []byte) {
	s.l.OnEvent(event, peerID, data)
}
