// Package punch implements UDP hole punching with a strategy matrix that
// handles every NAT combination, plus a relay fallback path.
package punch

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"

	"p2p/core/protocol"
	"p2p/core/stun"
)

// States reported through OnState.
const (
	StatePunching = "punching"
	StatePunched  = "punched"
	StateRelay    = "relay"
)

// WireGuardSink consumes a WireGuard datagram received on the punch socket. It
// is called from the read goroutine and must not block.
type WireGuardSink func(data []byte, src *net.UDPAddr)

// SetWireGuardSink attaches a tunnel to this socket, or detaches it when sink
// is nil. Packets are dropped rather than queued until a sink is attached.
func (p *Punch) SetWireGuardSink(sink WireGuardSink) {
	if sink == nil {
		p.wgHook.Store(nil)
		return
	}
	p.wgHook.Store(&sink)
}

// keepaliveInterval keeps established NAT mappings alive. It is shorter than
// common NAT mapping timeouts (30s–120s) while staying low-overhead.
const keepaliveInterval = 15 * time.Second

// peerIdleTimeout is how long a connected peer may stay silent before the
// link is considered stale and hole punching is restarted.
const peerIdleTimeout = 45 * time.Second

// Punch drives hole punching for a set of remote peers over one shared UDP
// socket.
type Punch struct {
	Conn   net.PacketConn
	MyID   protocol.PeerID
	My     NATInfo
	Config Config

	// OnData is called for inbound data packets (from the read goroutine).
	OnData func(src protocol.PeerID, pkt *Packet) error
	// OnState reports per-peer punching progress (from the read goroutine).
	// The third argument is the actual remote UDP endpoint (IP:port) used for
	// the connection, or an empty string when not available.
	OnState func(peerID protocol.PeerID, state string, endpoint string)
	// wgHook routes datagrams that are not punch frames to a WireGuard tunnel
	// sharing this socket -- and therefore this NAT mapping. Swapped atomically
	// because the tunnel may attach while the read loop is already running.
	wgHook atomic.Pointer[WireGuardSink]

	mu     sync.Mutex
	peers  map[protocol.PeerID]*peer
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	sendCh chan sendItem
}

type sendItem struct {
	endpoint *net.UDPAddr
	buf      []byte
}

type peer struct {
	info      NATInfo
	mu        sync.Mutex
	endpoint  *net.UDPAddr
	transport string
	connected bool
	seq       uint16
	relayOn   bool
	stop      chan struct{}
	lastSeen  time.Time
}

// New creates an idle Punch over conn.
func New(conn net.PacketConn, myID protocol.PeerID, my NATInfo, cfg Config) *Punch {
	return &Punch{
		Conn:   conn,
		MyID:   myID,
		My:     my,
		Config: cfg,
		sendCh: make(chan sendItem, 4096),
		peers:  make(map[protocol.PeerID]*peer),
		done:   make(chan struct{}),
	}
}

// logf emits a verbose punch-flow message when OnLog is configured.
func (p *Punch) logf(format string, args ...interface{}) {
	if p.Config.OnLog != nil {
		p.Config.OnLog(format, args...)
	}
}

// AddPeer registers a remote peer and starts probing it. If the peer already
// exists its info is refreshed and the old probe loop is stopped before a new
// one starts with the updated targets.
func (p *Punch) AddPeer(id protocol.PeerID, info NATInfo) {
	p.mu.Lock()
	ps, ok := p.peers[id]
	if !ok {
		ps = &peer{info: info, stop: make(chan struct{}), lastSeen: time.Now()}
		p.peers[id] = ps
		stop := ps.stop
		p.mu.Unlock()
		p.wg.Add(1)
		go p.probeLoop(id, stop)
		return
	}
	ps.mu.Lock()
	if ps.stop != nil {
		close(ps.stop)
	}
	ps.stop = make(chan struct{})
	stop := ps.stop
	ps.info = info
	ps.lastSeen = time.Now()
	ps.mu.Unlock()
	p.mu.Unlock()
	p.wg.Add(1)
	go p.probeLoop(id, stop)
}

// RemovePeer drops a remote peer and stops its probe loop.
func (p *Punch) RemovePeer(id protocol.PeerID) {
	p.mu.Lock()
	ps := p.peers[id]
	delete(p.peers, id)
	if ps != nil {
		ps.mu.Lock()
		if ps.stop != nil {
			close(ps.stop)
			ps.stop = nil
		}
		ps.mu.Unlock()
	}
	p.mu.Unlock()
}

// Start begins the shared read and batch-send loops.
func (p *Punch) Start() {
	p.wg.Add(1)
	go p.readLoop()
	p.wg.Add(1)
	go p.sendLoop()
}

// RegisterRelay sends a relay registration packet so the relay learns our
// address. The payload carries "room\0token" so the shared relay socket can
// route to the right room. It keeps re-sending until ack'd or stopped.
func (p *Punch) RegisterRelay(relayAddr *net.UDPAddr, room, token string) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		payload := []byte(room + "\x00" + token)
		ticker := time.NewTicker(time.Duration(p.intervalMs()) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
			}
			pkt := &Packet{Type: PktRegister, Src: p.MyID, Dst: protocol.PeerID{}, Payload: payload}
			buf := encodePooled(pkt)
			p.Conn.WriteTo(buf, relayAddr)
			putEncode(buf)
		}
	}()
}

func (p *Punch) intervalMs() int {
	if p.Config.ProbeIntervalMs <= 0 {
		return 200
	}
	return p.Config.ProbeIntervalMs
}

func (p *Punch) punchTimeout() time.Duration {
	if p.Config.PunchTimeoutMs <= 0 {
		return 4 * time.Second
	}
	return time.Duration(p.Config.PunchTimeoutMs) * time.Millisecond
}

// Send delivers a data payload to a connected peer.
func (p *Punch) Send(id protocol.PeerID, data []byte) error {
	ps := p.peer(id)
	if ps == nil {
		return errors.New("punch: unknown peer")
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if !ps.connected || ps.endpoint == nil {
		return errors.New("punch: peer not connected")
	}
	ps.seq++
	pkt := &Packet{Type: PktData, Seq: ps.seq, Src: p.MyID, Dst: id, Payload: data}
	buf := encodePooled(pkt)
	select {
	case p.sendCh <- sendItem{endpoint: ps.endpoint, buf: buf}:
		return nil
	default:
		// Queue is full: fall back to an immediate write to avoid blocking the
		// caller. This should be rare; the batch writer drains continuously.
		_, err := p.Conn.WriteTo(buf, ps.endpoint)
		putEncode(buf)
		return err
	}
}

const (
	sendBatchSize     = 64
	sendBatchInterval = time.Millisecond
)

// sendLoop batches outbound UDP datagrams and flushes them with sendmmsg
// (WriteBatch) where supported. This reduces syscall overhead dramatically on
// high-packet-rate paths such as Android TUN bridging.
func (p *Punch) sendLoop() {
	defer p.wg.Done()
	var batchWriter *ipv4.PacketConn
	if uc, ok := p.Conn.(*net.UDPConn); ok {
		batchWriter = ipv4.NewPacketConn(uc)
	}
	msgs := make([]ipv4.Message, 0, sendBatchSize)
	ticker := time.NewTicker(sendBatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			p.flushBatch(msgs, batchWriter)
			return
		case item := <-p.sendCh:
			msgs = append(msgs, ipv4.Message{Addr: item.endpoint, Buffers: [][]byte{item.buf}})
			// Coalesce everything already queued, then send at once. Blocking on
			// the ticker instead would add its full interval to every isolated
			// packet's latency.
		drain:
			for len(msgs) < sendBatchSize {
				select {
				case more := <-p.sendCh:
					msgs = append(msgs, ipv4.Message{Addr: more.endpoint, Buffers: [][]byte{more.buf}})
				default:
					break drain
				}
			}
			p.flushBatch(msgs, batchWriter)
			msgs = msgs[:0]
		case <-ticker.C:
			if len(msgs) > 0 {
				p.flushBatch(msgs, batchWriter)
				msgs = msgs[:0]
			}
		}
	}
}

func (p *Punch) flushBatch(msgs []ipv4.Message, batchWriter *ipv4.PacketConn) {
	if len(msgs) == 0 {
		return
	}
	if batchWriter != nil {
		if _, err := batchWriter.WriteBatch(msgs, 0); err == nil {
			for _, m := range msgs {
				if len(m.Buffers) > 0 {
					putEncode(m.Buffers[0])
				}
			}
			return
		}
		// WriteBatch is not supported on this platform/conn; fall back to
		// individual writes so packets are not silently dropped.
	}
	for _, m := range msgs {
		if m.Addr != nil && len(m.Buffers) > 0 {
			_, _ = p.Conn.WriteTo(m.Buffers[0], m.Addr)
		}
	}
	for _, m := range msgs {
		if len(m.Buffers) > 0 {
			putEncode(m.Buffers[0])
		}
	}
}

// Connected reports whether the peer has a confirmed endpoint.
func (p *Punch) Connected(id protocol.PeerID) (bool, string) {
	ps := p.peer(id)
	if ps == nil {
		return false, ""
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.connected, ps.transport
}

func (p *Punch) peer(id protocol.PeerID) *peer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peers[id]
}

// probeLoop probes all targets for one peer until connected or the peer's
// generation is replaced/removed.
func (p *Punch) probeLoop(id protocol.PeerID, stop <-chan struct{}) {
	defer p.wg.Done()
	ps := p.peer(id)
	if ps == nil {
		return
	}
	ps.mu.Lock()
	info := ps.info
	ps.mu.Unlock()

	cfg := p.Config

	// Symmetric-to-symmetric punching is unreliable even with port
	// prediction: the guessed mapping may create a link that immediately
	// goes stale. Such pairs go straight to the relay when available,
	// otherwise they are left to the mesh's multi-hop routing.
	bothSymmetric := p.My.Type == stun.NatSymmetric && info.Type == stun.NatSymmetric
	if bothSymmetric && !cfg.RelayFallback {
		return // no direct link; the mesh reaches this peer via hops
	}

	targets := planTargets(p.My, info, cfg)
	var punchEps []Endpoint
	var relayEp *Endpoint
	for i := range targets {
		if targets[i].Kind == "relay" {
			relayEp = &targets[i]
		} else {
			punchEps = append(punchEps, targets[i])
		}
	}

	relayOnly := bothSymmetric
	if relayOnly {
		punchEps = nil
	}

	interval := time.Duration(p.intervalMs()) * time.Millisecond

	// Verbose flow log: the punching plan for this peer.
	p.logf("peer %s (nat=%s): my private=%s peer private=%s", id.String()[:8], info.Type, p.My.PrivateAddr, info.PrivateAddr)
	p.logf("peer %s (nat=%s): punching plan", id.String()[:8], info.Type)
	for _, ep := range punchEps {
		p.logf("  target kind=%s %s", ep.Kind, ep.Addr)
	}
	if relayEp != nil {
		if relayOnly {
			p.logf("  symmetric-to-symmetric: relay only")
		} else {
			p.logf("  dual-path relay %s (parallel with direct punching)", relayEp.Addr)
		}
	}

	start := time.Now()
	lastAnnounce := time.Time{}
	for {
		if p.stopped() {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		if ok, _ := p.Connected(id); ok {
			p.keepaliveLoop(id, stop)
			return
		}
		eps := punchEps
		useRelay := relayEp != nil
		if useRelay {
			if !ps.relayOn {
				p.logf("peer %s: probing direct + relay in parallel", id.String()[:8])
			}
			ps.mu.Lock()
			ps.relayOn = true
			ps.mu.Unlock()
			eps = append(append([]Endpoint(nil), eps...), *relayEp)
		}
		for _, ep := range eps {
			if p.stopped() {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
			p.sendProbe(ps, ep)
		}
		// periodic activity heartbeat
		if time.Since(lastAnnounce) > 2*time.Second {
			lastAnnounce = time.Now()
			p.logf("peer %s: still probing %d target(s) (round %d)", id.String()[:8], len(eps), int(time.Since(start)/interval))
		}
		select {
		case <-p.done:
			return
		case <-stop:
			return
		case <-time.After(interval):
		}
	}
}

// keepaliveLoop maintains an established peer's NAT mapping. It sends a
// lightweight ack addressed to that peer on the confirmed endpoint until the
// peer is removed or the engine stops. Using PktAck with a non-zero dst keeps
// relay broadcasts from being accepted by other room members.
func (p *Punch) keepaliveLoop(id protocol.PeerID, stop <-chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-stop:
			return
		case <-ticker.C:
		}
		ps := p.peer(id)
		if ps == nil {
			return
		}
		ps.mu.Lock()
		if !ps.connected || ps.endpoint == nil {
			ps.mu.Unlock()
			return
		}
		if time.Since(ps.lastSeen) > peerIdleTimeout {
			ps.connected = false
			ps.transport = ""
			ps.mu.Unlock()
			p.logf("peer %s: idle for %s, restarting hole punch", id.String()[:8], peerIdleTimeout)
			p.restartPeer(id)
			return
		}
		endpoint := ps.endpoint
		ps.seq++
		seq := ps.seq
		ps.mu.Unlock()
		pkt := &Packet{Type: PktAck, Seq: seq, Src: p.MyID, Dst: id}
		buf := encodePooled(pkt)
		p.Conn.WriteTo(buf, endpoint)
		putEncode(buf)
	}
}

// restartPeer stops the current probe/keepalive generation for a peer and
// starts a fresh probe loop with the latest NAT info. Used after a connected
// peer goes idle for too long.
func (p *Punch) restartPeer(id protocol.PeerID) {
	p.mu.Lock()
	ps := p.peers[id]
	if ps == nil {
		p.mu.Unlock()
		return
	}
	ps.mu.Lock()
	if ps.stop != nil {
		close(ps.stop)
	}
	ps.stop = make(chan struct{})
	stop := ps.stop
	ps.mu.Unlock()
	p.mu.Unlock()
	p.wg.Add(1)
	go p.probeLoop(id, stop)
}

func (p *Punch) sendProbe(ps *peer, ep Endpoint) {
	ps.mu.Lock()
	ps.seq++
	seq := ps.seq
	ps.mu.Unlock()
	pkt := &Packet{Type: PktProbe, Seq: seq, Src: p.MyID, Dst: protocol.PeerID{}, Payload: nil}
	// dst unknown until we learn the peer's id; carry it in payload? No -
	// peers are identified by Src, so dst is only meaningful for data.
	// Use dst = zero; routing is by Src on receipt.
	buf := encodePooled(pkt)
	p.Conn.WriteTo(buf, ep.Addr)
	putEncode(buf)
}

func (p *Punch) readLoop() {
	defer p.wg.Done()
	bufs := make([][]byte, readBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	for {
		batches, err := readBatch(p.Conn, bufs)
		if err != nil {
			return
		}
		for _, bp := range batches {
			if IsWireGuard(bp.data) {
				if sink := p.wgHook.Load(); sink != nil {
					if ua, ok := bp.src.(*net.UDPAddr); ok {
						(*sink)(bp.data, ua)
					}
				}
				continue
			}
			pkt, err := Decode(bp.data)
			if err != nil {
				continue
			}
			switch pkt.Type {
			case PktProbe, PktProbe2, PktAck, PktData:
				// probes carry an empty dst; acks/data are addressed to us
				if pkt.Dst != p.MyID && pkt.Dst != (protocol.PeerID{}) {
					continue
				}
			case PktRegister:
				// only the relay server consumes registers
				continue
			case PktRegAck:
				if pkt.Dst != p.MyID {
					continue
				}
			}
			p.handle(pkt, bp.src)
		}
	}
}

func (p *Punch) handle(pkt *Packet, src net.Addr) {
	ua, _ := src.(*net.UDPAddr)

	switch pkt.Type {
	case PktRegAck:
		// relay registration confirmed; nothing else to do here
		return
	case PktRegister:
		// handled by the relay server, not the client engine
		return
	}

	// Only accept traffic from peers we are punching.
	ps := p.peer(pkt.Src)
	if ps == nil {
		return
	}
	ps.mu.Lock()
	ps.lastSeen = time.Now()
	switch pkt.Type {
	case PktProbe, PktProbe2:
		first := !ps.connected
		ps.endpoint = ua
		ps.transport = p.classifyTransport(ps, ua)
		ps.connected = true
		ps.mu.Unlock()
		if first {
			p.logf("peer %s: <- probe from %s -> connected via %s", pkt.Src.String()[:8], ua, ps.transport)
		}
		// answer with an ack to open the return path
		ack := &Packet{Type: PktAck, Seq: pkt.Seq, Src: p.MyID, Dst: pkt.Src}
		buf := encodePooled(ack)
		p.Conn.WriteTo(buf, ua)
		putEncode(buf)
		p.report(ps, pkt.Src)
		return
	case PktAck:
		first := !ps.connected
		ps.endpoint = ua
		ps.transport = p.classifyTransport(ps, ua)
		ps.connected = true
		ps.mu.Unlock()
		if first {
			p.logf("peer %s: <- ack from %s -> connected via %s", pkt.Src.String()[:8], ua, ps.transport)
		}
		p.report(ps, pkt.Src)
		return
	case PktData:
		first := !ps.connected
		if !ps.connected {
			ps.endpoint = ua
			ps.transport = p.classifyTransport(ps, ua)
			ps.connected = true
		}
		ps.mu.Unlock()
		if first {
			p.report(ps, pkt.Src)
		}
		if p.OnData != nil {
			p.OnData(pkt.Src, pkt)
		}
	}
}

// classifyTransport labels an endpoint as relay or punched. Caller must hold
// ps.mu.
func (p *Punch) classifyTransport(ps *peer, ua *net.UDPAddr) string {
	if ua == nil {
		return ""
	}
	if ps.info.RelayAddr != nil && ua.IP.Equal(ps.info.RelayAddr.IP) && ua.Port == ps.info.RelayAddr.Port {
		return StateRelay
	}
	return StatePunched
}

func (p *Punch) report(ps *peer, id protocol.PeerID) {
	if p.OnState == nil {
		return
	}
	ps.mu.Lock()
	t := ps.transport
	endpoint := ""
	if ps.endpoint != nil {
		endpoint = ps.endpoint.String()
	}
	ps.mu.Unlock()
	p.OnState(id, t, endpoint)
}

func (p *Punch) stopped() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Stop halts all loops and releases the engine.
func (p *Punch) Stop() {
	p.once.Do(func() {
		close(p.done)
		p.wg.Wait()
	})
}
