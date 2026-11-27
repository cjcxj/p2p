// Package punch implements pure UDP hole punching with a strategy matrix
// engineered for NAT3 (Port-Restricted Cone) to NAT4 (Symmetric / CGNAT)
// direct traversal.
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

const (
	keepaliveInterval    = 15 * time.Second
	symKeepaliveInterval = 5 * time.Second
	peerIdleTimeout      = 45 * time.Second
	defaultPunchPPS      = 1500
	refreshAnchorEvery   = 10 * time.Second
	upgradeProbeWindow   = 3 * time.Second
	upgradeProbeInterval = 80 * time.Millisecond
)

// Punch drives hole punching for a set of remote peers over one or more shared
// UDP sockets (plus optional IPv6 dual-stack socket).
type Punch struct {
	Conn     net.PacketConn
	Conns    []net.PacketConn // socket pool; Conns[0] == Conn after Start
	IPv6Conn net.PacketConn   // optional dual-stack IPv6 UDP socket (sockIdx = -1)
	MyID     protocol.PeerID
	My       NATInfo
	Config   Config

	OnData func(src protocol.PeerID, pkt *Packet) error
	OnState func(peerID protocol.PeerID, state string, endpoint string)
	// OnRefreshNeeded is invoked periodically while a peer remains unconnected
	// (e.g. rotating CGNAT) so the caller can re-probe STUN and push a fresh anchor.
	OnRefreshNeeded func(peerID protocol.PeerID)
	// OnDirectConfirmed is invoked when a direct path is locked via PktAck on sockIdx.
	OnDirectConfirmed func(peerID protocol.PeerID, sockIdx int)

	wgHook atomic.Pointer[WireGuardSink]

	mu     sync.Mutex
	peers  map[protocol.PeerID]*peer
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	sendCh chan sendItem
}

type sendItem struct {
	sockIdx  int
	endpoint *net.UDPAddr
	buf      []byte
}

type probeStamp struct {
	seq  uint16
	sent time.Time
	ok   bool
}

type peer struct {
	info      NATInfo
	mu        sync.Mutex
	endpoint  *net.UDPAddr
	sockIdx   int // which Conns entry carries this peer's data path (-1 = IPv6Conn)
	transport string
	tier      routeTier
	rtt       time.Duration
	connected bool
	confirmed bool // true once a PktAck or bidirectional handshake locked endpoint+sockIdx
	seq       uint16
	stop      chan struct{}
	lastSeen  time.Time
	probeSent [512]probeStamp
}

func (ps *peer) nextProbeSeqLocked() uint16 {
	ps.seq++
	if ps.seq == 0 {
		ps.seq = 1
	}
	ps.probeSent[ps.seq&511] = probeStamp{seq: ps.seq, sent: time.Now(), ok: true}
	return ps.seq
}

func (ps *peer) measureRTTLocked(seq uint16) time.Duration {
	if seq == 0 {
		return 0
	}
	st := ps.probeSent[seq&511]
	if !st.ok || st.seq != seq || st.sent.IsZero() {
		return 0
	}
	d := time.Since(st.sent)
	if d < time.Microsecond {
		// Windows and fast loopback can complete a probe round-trip within a
		// single clock tick (0ns); clamp to 1µs so confirmed RTT stays > 0.
		return time.Microsecond
	}
	return d
}

// New creates an idle Punch over conn. The single socket is installed as the
// pool right away: AddPeer starts probing immediately, so a caller that adds a
// peer before Start must already find a socket to write through.
func New(conn net.PacketConn, myID protocol.PeerID, my NATInfo, cfg Config) *Punch {
	return &Punch{
		Conn:   conn,
		Conns:  []net.PacketConn{conn},
		MyID:   myID,
		My:     my,
		Config: cfg,
		sendCh: make(chan sendItem, 8192),
		peers:  make(map[protocol.PeerID]*peer),
		done:   make(chan struct{}),
	}
}

func (p *Punch) logf(format string, args ...interface{}) {
	if p.Config.OnLog != nil {
		p.Config.OnLog(format, args...)
	}
}

func (p *Punch) connFor(sockIdx int) net.PacketConn {
	if sockIdx == -1 && p.IPv6Conn != nil {
		return p.IPv6Conn
	}
	if sockIdx >= 0 && sockIdx < len(p.Conns) && p.Conns[sockIdx] != nil {
		return p.Conns[sockIdx]
	}
	return p.Conn
}

// AddPeer registers a remote peer and starts probing it. If the peer already
// exists, the probe loop restarts against the refreshed candidate and clears any
// stale link state from the previous session.
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
	// Reaching an existing peer here means the far side restarted: a candidate is
	// only ever (re)sent when a node newly discovers us, and the server forwards
	// it verbatim without replaying it to anyone already connected. Clearing the
	// old endpoint, tier, and connected flag prevents the "disconnect, reconnect,
	// never reconnects again" deadlock.
	ps.connected = false
	ps.confirmed = false
	ps.transport = ""
	ps.tier = tierNone
	ps.rtt = 0
	ps.endpoint = nil
	ps.sockIdx = 0
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
	if len(p.Conns) == 0 {
		p.Conns = []net.PacketConn{p.Conn}
	}
	for i, conn := range p.Conns {
		if conn == nil {
			continue
		}
		p.wg.Add(1)
		go p.readLoop(conn, i)
	}
	if p.IPv6Conn != nil {
		p.wg.Add(1)
		go p.readLoop(p.IPv6Conn, -1)
	}
	p.wg.Add(1)
	go p.sendLoop()
}

func (p *Punch) intervalMs() int {
	if p.Config.ProbeIntervalMs <= 0 {
		return 80
	}
	return p.Config.ProbeIntervalMs
}

func (p *Punch) punchPPS() int {
	if p.Config.PunchPPS <= 0 {
		return defaultPunchPPS
	}
	return p.Config.PunchPPS
}

func (p *Punch) escalateAfter() time.Duration {
	if p.Config.EscalateAfterMs > 0 {
		return time.Duration(p.Config.EscalateAfterMs) * time.Millisecond
	}
	return 2000 * time.Millisecond
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
	case p.sendCh <- sendItem{sockIdx: ps.sockIdx, endpoint: ps.endpoint, buf: buf}:
		return nil
	default:
		_, err := p.connFor(ps.sockIdx).WriteTo(buf, ps.endpoint)
		putEncode(buf)
		return err
	}
}

const (
	sendBatchSize     = 64
	sendBatchInterval = time.Millisecond
)

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
			if item.sockIdx != 0 {
				_, _ = p.connFor(item.sockIdx).WriteTo(item.buf, item.endpoint)
				putEncode(item.buf)
				continue
			}
			msgs = append(msgs, ipv4.Message{Addr: item.endpoint, Buffers: [][]byte{item.buf}})
		drain:
			for len(msgs) < sendBatchSize {
				select {
				case more := <-p.sendCh:
					if more.sockIdx != 0 {
						_, _ = p.connFor(more.sockIdx).WriteTo(more.buf, more.endpoint)
						putEncode(more.buf)
						continue
					}
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

// PeerRoute returns the currently selected route tier ("lan","ipv6","upnp",
// "public","none"), active remote endpoint, and last measured RTT.
func (p *Punch) PeerRoute(id protocol.PeerID) (tier string, endpoint string, rtt time.Duration) {
	ps := p.peer(id)
	if ps == nil {
		return tierNone.String(), "", 0
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.endpoint != nil {
		endpoint = ps.endpoint.String()
	}
	return ps.tier.String(), endpoint, ps.rtt
}

func (p *Punch) routeState(id protocol.PeerID) (connected, confirmed bool, transport string, tier routeTier) {
	ps := p.peer(id)
	if ps == nil {
		return false, false, "", tierNone
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.connected, ps.confirmed, ps.transport, ps.tier
}

// SendWireGuard writes an outbound WireGuard datagram to dst through the socket
// that actually punched the peer owning that endpoint.
func (p *Punch) SendWireGuard(buf []byte, dst *net.UDPAddr) error {
	if dst == nil {
		return errors.New("punch: nil wireguard destination")
	}
	idx := 0
	target := dst.String()
	p.mu.Lock()
	for _, ps := range p.peers {
		ps.mu.Lock()
		if ps.connected && ps.transport == StatePunched && ps.endpoint != nil &&
			ps.endpoint.String() == target {
			idx = ps.sockIdx
		}
		ps.mu.Unlock()
	}
	p.mu.Unlock()
	_, err := p.connFor(idx).WriteTo(buf, dst)
	return err
}

func (p *Punch) peer(id protocol.PeerID) *peer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peers[id]
}

// probeLoop probes all targets for one peer until a direct link is established.
// In pure-P2P mode, it never gives up: after an intense initial window it
// settles into a steady low-overhead direct probe cadence and triggers
// periodic NAT anchor refreshes.
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
	var deck *portDeck
	if info.isHardNAT() && cfg.SymmetricSpray >= 0 {
		deck = newPortDeck(nil)
	}

	var batchWriter0 *ipv4.PacketConn
	if uc, ok := p.Conn.(*net.UDPConn); ok {
		batchWriter0 = ipv4.NewPacketConn(uc)
	}

	targets := planTargetsWithDeck(p.My, info, cfg, deck, 0)
	var punchEps []Endpoint
	spraying := false
	for i := range targets {
		if targets[i].Kind == "spray" {
			spraying = true
		}
		punchEps = append(punchEps, targets[i])
	}

	p.logf("peer %s (nat=%s): my private=%s peer private=%s", id.String()[:8], info.Type, p.My.PrivateAddr, info.PrivateAddr)
	p.logf("peer %s (nat=%s): punching plan (%d targets, pps=%d)", id.String()[:8], info.Type, len(punchEps), p.punchPPS())
	counts := map[string]int{}
	for _, ep := range punchEps {
		counts[ep.Kind]++
	}
	for kind, cnt := range counts {
		p.logf("  leg=%s targets=%d", kind, cnt)
	}

	interval := time.Duration(p.intervalMs()) * time.Millisecond
	pps := p.punchPPS()
	escalateAfter := p.escalateAfter()
	escalated := false
	planMy := p.My
	planInfo := info
	maxTier := maxPlannedTier(punchEps)
	start := time.Now()
	var directConfirmedAt time.Time
	lastAnnounce := time.Time{}
	lastRefresh := start
	round := 0

	for {
		if p.stopped() {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		connected, confirmed, _, curTier := p.routeState(id)
		var upgradeEps []Endpoint
		if connected && confirmed {
			if directConfirmedAt.IsZero() {
				directConfirmedAt = time.Now()
			}
			if curTier < maxTier && time.Since(directConfirmedAt) < upgradeProbeWindow {
				upgradeEps = filterHigherTierEndpoints(punchEps, curTier)
			}
			if len(upgradeEps) == 0 {
				p.keepaliveLoop(id, stop)
				return
			}
		}

		if !connected && !spraying && !escalated && time.Since(start) >= escalateAfter {
			escalated = true
			planMy.Type = stun.NatSymmetric
			planInfo.Type = stun.NatSymmetric
			if deck == nil && cfg.SymmetricSpray >= 0 {
				deck = newPortDeck(nil)
			}
			nt := planTargetsWithDeck(planMy, planInfo, cfg, deck, round)
			replanned := punchEps[:0]
			for i := range nt {
				if nt[i].Kind == "spray" {
					spraying = true
				}
				replanned = append(replanned, nt[i])
			}
			punchEps = replanned
			maxTier = maxPlannedTier(punchEps)
			p.logf("peer %s: not connected after %s, escalating both ends to hard plant+spray", id.String()[:8], escalateAfter)
		}

		wait := interval
		if round > 0 && time.Since(start) > 25*time.Second && wait < 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}

		if !confirmed && round > 0 && (deck != nil || planInfo.PoolCIDR != nil || planMy.isHardNAT()) {
			nt := planTargetsWithDeck(planMy, planInfo, cfg, deck, round)
			punchEps = append(punchEps[:0], nt...)
			maxTier = maxPlannedTier(punchEps)
		}

		eps := punchEps
		if len(upgradeEps) > 0 {
			// Active lower-tier direct link already works; keep it warm while
			// probing strictly higher-tier candidates (LAN / IPv6 / UPnP) only.
			p.keepAliveOnce(id)
			eps = upgradeEps
			if wait < upgradeProbeInterval {
				wait = upgradeProbeInterval
			}
		}

		p.sendBurst(ps, eps, batchWriter0, pps, stop)
		round++

		if !connected && p.OnRefreshNeeded != nil && time.Since(lastRefresh) >= refreshAnchorEvery {
			lastRefresh = time.Now()
			go p.OnRefreshNeeded(id)
		}

		if time.Since(lastAnnounce) > 2*time.Second {
			lastAnnounce = time.Now()
			p.logf("peer %s: probing %d targets (round %d)", id.String()[:8], len(eps), round)
		}

		select {
		case <-p.done:
			return
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}

// sendBurst dispatches eps with Socket 0 batched via WriteBatch and rate-paced
// at pps packets/sec so NATs and kernel buffers do not drop bursts.
func (p *Punch) sendBurst(ps *peer, eps []Endpoint, batchWriter0 *ipv4.PacketConn, pps int, stop <-chan struct{}) {
	const chunkSize = 32
	var chunk []ipv4.Message
	var chunkBufs [][]byte
	if batchWriter0 != nil {
		chunk = make([]ipv4.Message, 0, chunkSize)
		chunkBufs = make([][]byte, 0, chunkSize)
	}

	sentSincePace := 0
	paceStart := time.Now()
	paceStep := 32

	pace := func() bool {
		sentSincePace++
		if pps <= 0 || sentSincePace < paceStep {
			return true
		}
		targetDur := time.Duration(sentSincePace) * time.Second / time.Duration(pps)
		if elapsed := time.Since(paceStart); targetDur > elapsed {
			d := targetDur - elapsed
			if d > 20*time.Millisecond {
				d = 20 * time.Millisecond
			}
			select {
			case <-p.done:
				return false
			case <-stop:
				return false
			case <-time.After(d):
			}
		}
		if sentSincePace >= 256 {
			sentSincePace = 0
			paceStart = time.Now()
		}
		return true
	}

	flushChunk := func() {
		if len(chunk) == 0 {
			return
		}
		if _, err := batchWriter0.WriteBatch(chunk, 0); err != nil {
			for _, m := range chunk {
				if m.Addr != nil && len(m.Buffers) > 0 {
					_, _ = p.Conn.WriteTo(m.Buffers[0], m.Addr)
				}
			}
		}
		for _, b := range chunkBufs {
			putEncode(b)
		}
		chunk = chunk[:0]
		chunkBufs = chunkBufs[:0]
	}

	for _, ep := range eps {
		if p.stopped() {
			flushChunk()
			return
		}
		select {
		case <-stop:
			flushChunk()
			return
		default:
		}
		if !pace() {
			flushChunk()
			return
		}

		ps.mu.Lock()
		seq := ps.nextProbeSeqLocked()
		ps.mu.Unlock()

		pkt := &Packet{Type: PktProbe, Seq: seq, Src: p.MyID, Dst: protocol.PeerID{}}
		buf := encodePooled(pkt)
		if ep.Socket == 0 && batchWriter0 != nil {
			chunk = append(chunk, ipv4.Message{Addr: ep.Addr, Buffers: [][]byte{buf}})
			chunkBufs = append(chunkBufs, buf)
			if len(chunk) >= chunkSize {
				flushChunk()
			}
			continue
		}
		_, _ = p.connFor(ep.Socket).WriteTo(buf, ep.Addr)
		putEncode(buf)
	}
	flushChunk()
}

func (p *Punch) keepaliveLoop(id protocol.PeerID, stop <-chan struct{}) {
	ps := p.peer(id)
	iv := keepaliveInterval
	if ps != nil {
		ps.mu.Lock()
		if p.My.isHardNAT() || ps.info.isHardNAT() {
			iv = symKeepaliveInterval
		}
		ps.mu.Unlock()
	}

	ticker := time.NewTicker(iv)
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
		if !ps.connected {
			ps.mu.Unlock()
			return
		}
		if time.Since(ps.lastSeen) > peerIdleTimeout {
			ps.connected = false
			ps.confirmed = false
			ps.transport = ""
			ps.tier = tierNone
			ps.rtt = 0
			ps.mu.Unlock()
			p.logf("peer %s: idle for %s, restarting hole punch", id.String()[:8], peerIdleTimeout)
			p.restartPeer(id)
			return
		}
		ps.mu.Unlock()
		if !p.keepAliveOnce(id) {
			return
		}
	}
}

func (p *Punch) keepAliveOnce(id protocol.PeerID) bool {
	ps := p.peer(id)
	if ps == nil {
		return false
	}
	ps.mu.Lock()
	if !ps.connected || ps.endpoint == nil {
		ps.mu.Unlock()
		return false
	}
	endpoint := ps.endpoint
	sockIdx := ps.sockIdx
	ps.mu.Unlock()
	// Use Seq=0 for unsolicited keepalives so peer's probe-ack RTT tracker
	// never confuses keepalives with echoed PktProbe sequence numbers.
	pkt := &Packet{Type: PktAck, Seq: 0, Src: p.MyID, Dst: id}
	buf := encodePooled(pkt)
	_, _ = p.connFor(sockIdx).WriteTo(buf, endpoint)
	putEncode(buf)
	return true
}

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
	seq := ps.nextProbeSeqLocked()
	ps.mu.Unlock()
	pkt := &Packet{Type: PktProbe, Seq: seq, Src: p.MyID, Dst: protocol.PeerID{}, Payload: nil}
	buf := encodePooled(pkt)
	_, _ = p.connFor(ep.Socket).WriteTo(buf, ep.Addr)
	putEncode(buf)
}

func (p *Punch) readLoop(conn net.PacketConn, sockIdx int) {
	defer p.wg.Done()
	bufs := make([][]byte, readBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	for {
		var (
			batches []batchPacket
			err     error
		)
		if sockIdx < 0 {
			batches, err = readBatchSingle(conn, bufs[0])
		} else {
			batches, err = readBatch(conn, bufs)
		}
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
				if pkt.Dst != p.MyID && pkt.Dst != (protocol.PeerID{}) {
					continue
				}
			}
			p.handle(pkt, bp.src, sockIdx)
		}
	}
}

func (p *Punch) handle(pkt *Packet, src net.Addr, sockIdx int) {
	ua, _ := src.(*net.UDPAddr)

	ps := p.peer(pkt.Src)
	if ps == nil {
		return
	}
	ps.mu.Lock()
	switch pkt.Type {
	case PktProbe, PktProbe2:
		prevTier := ps.tier
		wasConfirmed := ps.confirmed
		sameAddr := ps.endpoint != nil && ua != nil && ps.endpoint.IP.Equal(ua.IP) && ps.endpoint.Port == ua.Port && ps.sockIdx == sockIdx
		probeTier := classifyPacketTier(p.My, ps.info, p.Config, ua, sockIdx)
		first, upgraded, _ := ps.note(p, ua, sockIdx, false, 0)
		// Only refresh liveness from one-way probes if we are not yet confirmed
		// or the probe came from the active path / caused a transition; otherwise
		// a stray or roaming probe would keep lastSeen alive while being ignored
		// and defeat peerIdleTimeout recovery.
		if !wasConfirmed || sameAddr || first || upgraded {
			ps.lastSeen = time.Now()
		}
		transport := ps.transport
		confirmed := ps.confirmed
		newTier := ps.tier
		ps.mu.Unlock()
		if first || upgraded {
			p.logf("peer %s: <- probe from %s -> connected via %s[%s] (socket %d)", pkt.Src.String()[:8], ua, transport, newTier, sockIdx)
		}
		ack := &Packet{Type: PktAck, Seq: pkt.Seq, Src: p.MyID, Dst: pkt.Src}
		buf := encodePooled(ack)
		_, _ = p.connFor(sockIdx).WriteTo(buf, ua)
		putEncode(buf)
		// If we are already confirmed on a lower tier and receive a higher-tier
		// probe (e.g. LAN/IPv6 arriving after Public), fire one opportunistic
		// reverse probe immediately so both sides confirm the upgrade in 1 RTT.
		if confirmed && probeTier > prevTier && ua != nil {
			p.sendProbe(ps, Endpoint{Addr: ua, Socket: sockIdx})
		}
		p.report(ps, pkt.Src)
		return
	case PktAck:
		ps.lastSeen = time.Now()
		sampleRTT := ps.measureRTTLocked(pkt.Seq)
		prevTier := ps.tier
		first, upgraded, notifyConfirmed := ps.note(p, ua, sockIdx, true, sampleRTT)
		transport := ps.transport
		confirmedSock := ps.sockIdx
		newTier := ps.tier
		rtt := ps.rtt
		ps.mu.Unlock()
		if first {
			p.logf("peer %s: <- ack from %s -> connected via %s[%s] (socket %d, rtt=%s)", pkt.Src.String()[:8], ua, transport, newTier, confirmedSock, rtt)
		} else if upgraded {
			p.logf("peer %s: <- ack from %s -> upgraded %s -> %s[%s] (socket %d, rtt=%s)", pkt.Src.String()[:8], ua, prevTier, transport, newTier, confirmedSock, rtt)
		}
		p.report(ps, pkt.Src)
		if notifyConfirmed && p.OnDirectConfirmed != nil {
			p.OnDirectConfirmed(pkt.Src, confirmedSock)
		}
		return
	case PktData:
		ps.lastSeen = time.Now()
		first, upgraded, notifyConfirmed := ps.note(p, ua, sockIdx, true, 0)
		confirmedSock := ps.sockIdx
		ps.mu.Unlock()
		if first || upgraded {
			p.report(ps, pkt.Src)
		}
		if notifyConfirmed && p.OnDirectConfirmed != nil {
			p.OnDirectConfirmed(pkt.Src, confirmedSock)
		}
		if p.OnData != nil {
			p.OnData(pkt.Src, pkt)
		}
	}
}

// note records the endpoint, socket, and routeTier for a peer's packet.
// Routes obey strict ICE upgrade-only ordering (LAN > IPv6 > UPnP > Public):
// higher tiers always upgrade lower tiers once confirmed via PktAck/PktData,
// while lower-tier delayed packets or stray PktProbes never downgrade or hijack
// an already-confirmed direct link. Caller must hold ps.mu.
func (ps *peer) note(p *Punch, ua *net.UDPAddr, sockIdx int, isAckOrData bool, sampleRTT time.Duration) (first, upgraded, notifyConfirmed bool) {
	first = !ps.connected
	if ua == nil {
		return first, false, false
	}
	newTier := classifyPacketTier(p.My, ps.info, p.Config, ua, sockIdx)

	// Strictly non-downgrading: once connected on a higher tier (e.g. LAN/IPv6
	// vs Public), lower-tier packets never overwrite it.
	if ps.connected && newTier < ps.tier {
		return false, false, false
	}

	// Same address & socket refresh: confirm or update RTT without churning.
	sameAddr := ps.endpoint != nil && ps.endpoint.IP.Equal(ua.IP) && ps.endpoint.Port == ua.Port && ps.sockIdx == sockIdx

	if ps.confirmed && ps.transport == StatePunched {
		// Never let one-way PktProbes overwrite an already-confirmed direct path,
		// even on a higher tier; wait for bidirectional PktAck/PktData so a broken
		// half-open route cannot disrupt live traffic.
		if !isAckOrData && !sameAddr {
			return false, false, false
		}
	}

	prevTier := ps.tier
	prevSock := ps.sockIdx
	prevEp := ps.endpoint

	if sameAddr {
		if sampleRTT > 0 {
			ps.rtt = sampleRTT
		}
		if isAckOrData && !ps.confirmed {
			ps.confirmed = true
			notifyConfirmed = true
		}
		return false, false, notifyConfirmed
	}

	ps.endpoint = ua
	ps.sockIdx = sockIdx
	ps.tier = newTier
	if sampleRTT > 0 {
		ps.rtt = sampleRTT
	} else if prevTier != tierNone && newTier > prevTier {
		ps.rtt = 0
	}
	ps.transport = StatePunched
	if isAckOrData {
		wasConfirmed := ps.confirmed
		ps.confirmed = true
		endpointSwitched := prevEp == nil || !prevEp.IP.Equal(ua.IP) || prevEp.Port != ua.Port || prevSock != sockIdx
		if !wasConfirmed || (newTier > prevTier && endpointSwitched) {
			notifyConfirmed = true
		}
	}
	ps.connected = true
	upgraded = prevTier != tierNone && newTier > prevTier
	return first, upgraded, notifyConfirmed
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
