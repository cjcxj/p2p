// Package punch implements UDP hole punching with a strategy matrix that
// handles every NAT combination. Pure P2P: there is no relay fallback.
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

// States reported through OnState. Pure P2P: a link is either still punching or
// punched -- there is no relay state.
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

// keepaliveInterval keeps established NAT mappings alive. It is shorter than
// common NAT mapping timeouts (30s–120s) while staying low-overhead.
const keepaliveInterval = 15 * time.Second

// peerIdleTimeout is how long a connected peer may stay silent before the
// link is considered stale and hole punching is restarted.
const peerIdleTimeout = 45 * time.Second

// Punch drives hole punching for a set of remote peers over one or more shared
// UDP sockets.
type Punch struct {
	Conn   net.PacketConn
	Conns  []net.PacketConn // socket pool; Conns[0] == Conn after Start
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
	sockIdx  int
	endpoint *net.UDPAddr
	buf      []byte
}

type peer struct {
	info      NATInfo
	mu        sync.Mutex
	endpoint  *net.UDPAddr
	sockIdx   int // which Conns entry carries this peer's data path
	transport string
	connected bool
	seq       uint16
	stop      chan struct{}
	lastSeen  time.Time
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
	// Reaching an existing peer here means the far side restarted: a candidate is
	// only ever (re)sent when a node newly discovers us, and the server forwards
	// it verbatim without replaying it to anyone already connected. The endpoint
	// and socket on record belong to the dead session. Leaving the peer marked
	// connected would send this fresh probe loop straight into keepalive mode on a
	// path the peer no longer uses -- and because a rejoined peer cannot reach us
	// until WE open its side of the mapping, its own probes would meet a closed
	// door for the whole idle timeout. That is the "disconnect, reconnect, never
	// reconnects again" deadlock.
	ps.connected = false
	ps.transport = ""
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
		p.wg.Add(1)
		go p.readLoop(conn, i)
	}
	p.wg.Add(1)
	go p.sendLoop()
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

// escalateMs is how long a soft (cone-classified) plan may run without
// connecting before we re-plan the peer as hard. A few seconds is enough for a
// true cone peer to have connected via its public address, so waiting this long
// before spraying only delays recovery from a misclassification and never
// slows a correctly-classified link.
func (p *Punch) escalateMs() int {
	if p.Config.EscalateAfterMs > 0 {
		return p.Config.EscalateAfterMs
	}
	return 3000
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
		_, err := p.Conns[ps.sockIdx].WriteTo(buf, ps.endpoint)
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
			if item.sockIdx != 0 {
				_, _ = p.Conns[item.sockIdx].WriteTo(item.buf, item.endpoint)
				putEncode(item.buf)
				continue
			}
			msgs = append(msgs, ipv4.Message{Addr: item.endpoint, Buffers: [][]byte{item.buf}})
		drain:
			for len(msgs) < sendBatchSize {
				select {
				case more := <-p.sendCh:
					if more.sockIdx != 0 {
						_, _ = p.Conns[more.sockIdx].WriteTo(more.buf, more.endpoint)
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

// SendWireGuard writes an outbound WireGuard datagram to dst through the socket
// that actually punched the peer owning that endpoint, so the frame shares the
// peer's live NAT mapping instead of a different pool socket's unmapped source.
// It falls back to the primary socket when the endpoint matches no punched peer
// (a relay link, or a peer mid-roaming before its endpoint is confirmed).
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
			ps.endpoint.String() == target && ps.sockIdx < len(p.Conns) {
			idx = ps.sockIdx
		}
		ps.mu.Unlock()
	}
	p.mu.Unlock()
	if idx >= len(p.Conns) {
		idx = 0
	}
	_, err := p.Conns[idx].WriteTo(buf, dst)
	return err
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

	// Pure P2P: there is no relay fallback, so every peer gets the full direct
	// attempt. canSpray (an active socket pool) enables the step-aligned and
	// n4 block legs; the multi-IP spray leg runs regardless of pool size, so a
	// destination-rotating CGNAT is still attacked even with a single socket.
	targets := planTargets(p.My, info, cfg, 0)
	var punchEps []Endpoint
	spraying := false
	for i := range targets {
		if targets[i].Kind == "spray" {
			spraying = true
		}
		punchEps = append(punchEps, targets[i])
	}

	interval := time.Duration(p.intervalMs()) * time.Millisecond

	// Verbose flow log: the punching plan for this peer. The spray window is
	// thousands of endpoints; collapse it to one line so the plan is readable.
	p.logf("peer %s (nat=%s): my private=%s peer private=%s", id.String()[:8], info.Type, p.My.PrivateAddr, info.PrivateAddr)
	p.logf("peer %s (nat=%s): punching plan", id.String()[:8], info.Type)
	sprayPorts := 0
	var sprayIP net.IP
	for _, ep := range punchEps {
		if ep.Kind == "spray" {
			sprayPorts++
			if sprayIP == nil {
				sprayIP = ep.Addr.IP
			}
			continue
		}
		p.logf("  target kind=%s %s", ep.Kind, ep.Addr)
	}
	if sprayPorts > 0 {
		p.logf("  target kind=spray %d random ports at %s (re-rolled each round)", sprayPorts, sprayIP)
	}
	start := time.Now()
	lastAnnounce := time.Time{}
	round := 0
	// Fail-safe escalation. A cellular symmetric NAT is flakily classified as
	// cone on real networks (the second-destination probe sometimes repeats the
	// mapping), and a "cone" verdict gives the peer only a single public probe
	// that never re-rolls -- so a misclassification permanently strands the
	// link. If a soft (non-spraying) plan has not connected within
	// escalateAfter, re-plan the peer as hard (plant+spray). This is additive:
	// a genuinely-cone peer would already be connected by now, so escalating it
	// costs only a little extra traffic and recovers the misdetected case.
	escalated := false
	escalateAfter := time.Duration(p.escalateMs()) * time.Millisecond
	// planInfo is the peer info the plan is built from; escalation switches it
	// from the (possibly misclassified) reported type to hard so every later
	// re-roll keeps the aggressive plan instead of reverting to the soft one.
	planInfo := info
	// planMy mirrors planInfo for our OWN side. A symmetric host can also be
	// flakily misdetected as cone, and then it never PLANTS (fans its socket
	// pool), leaving the peer a single external port to hit. Escalation forces
	// our own type hard too, so the full plant+spray birthday attack runs and
	// self-misdetection is recovered.
	planMy := p.My
	// Probe rate ceiling. A wide CGNAT spray is tens of thousands of targets a
	// round; blasting them as fast as the loop allows saturates the host NIC and
	// overflows the router's NAT conntrack table, which takes the entire network
	// offline. Pace the sweep instead -- EasyTier-class punching lands within
	// seconds at a couple thousand packets/s, so a cap costs nothing real.
	pps := cfg.PunchPPS
	if pps <= 0 {
		pps = defaultPunchPPS
	}
	pace := time.Second / time.Duration(pps)
	nextSend := time.Now()
	for {
		if p.stopped() {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		connected, transport := p.Connected(id)
		if connected && transport == StatePunched {
			p.keepaliveLoop(id, stop)
			return
		}
		if !spraying && !escalated && time.Since(start) > escalateAfter {
			escalated = true
			planInfo.Type = stun.NatSymmetric
			planMy.Type = stun.NatSymmetric
			nt := planTargets(planMy, planInfo, cfg, round)
			replanned := punchEps[:0]
			for i := range nt {
				if nt[i].Kind == "spray" {
					spraying = true
				}
				replanned = append(replanned, nt[i])
			}
			punchEps = replanned
			p.logf("peer %s: cone-classified peer not connected after %s, escalating to hard plant+spray", id.String()[:8], escalateAfter)
		}
		wait := interval
		if spraying && round > 0 {
			// Re-roll the spray window each round. A fixed random subset can
			// miss the peer's planted mapping ports forever; new ports every
			// round grow coverage until a collision lands.
			nt := planTargets(planMy, planInfo, cfg, round)
			replanned := punchEps[:0]
			replanned = append(replanned, nt...)
			punchEps = replanned
		}
		eps := punchEps
		nextSend = time.Now()
		for _, ep := range eps {
			if p.stopped() {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
			// Staggered plant/block refresh. A 128-socket plant pool re-sent in
			// full every round floods the cellular CGNAT's port quota / anti-flood
			// (measured: pps 3000 with full re-send dropped to 1/4). UDP mappings
			// live 15-60s, so after the first two rounds that spread every socket,
			// only a rotating 1/plantStaggerDiv slice needs refreshing each round to
			// keep them warm -- freeing the rate budget for the spray that actually
			// collides. Spray/predicted/public always send every round.
			if round >= 2 && (ep.Kind == "plant" || ep.Kind == "block") &&
				(ep.Socket+round)%plantStaggerDiv != 0 {
				continue
			}
			p.sendProbe(ps, ep)
			// Rate-limit the sweep: block until this probe's scheduled slot.
			nextSend = nextSend.Add(pace)
			if d := time.Until(nextSend); d > 0 {
				select {
				case <-p.done:
					return
				case <-stop:
					return
				case <-time.After(d):
				}
			}
		}
		round++
		// periodic activity heartbeat
		if time.Since(lastAnnounce) > 2*time.Second {
			lastAnnounce = time.Now()
			p.logf("peer %s: still probing %d target(s) (round %d)", id.String()[:8], len(eps), round)
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
		if !ps.connected {
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
		ps.mu.Unlock()
		if !p.keepAliveOnce(id) {
			return
		}
	}
}

// keepAliveOnce sends the one lightweight ack that maintains a connected
// peer's NAT mapping on its confirmed endpoint. Using PktAck with a non-zero
// dst keeps relay broadcasts from being accepted by other room members. It
// returns false when the peer is gone or is no longer connected.
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
	ps.seq++
	seq := ps.seq
	ps.mu.Unlock()
	pkt := &Packet{Type: PktAck, Seq: seq, Src: p.MyID, Dst: id}
	buf := encodePooled(pkt)
	p.Conns[sockIdx].WriteTo(buf, endpoint)
	putEncode(buf)
	return true
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
	buf := encodePooled(pkt)
	// A target planned against a wider pool than this engine has -- an AddPeer
	// that raced a pool swap -- still has to reach the peer on some socket, and
	// indexing past the end would take the whole process down.
	idx := ep.Socket
	if idx >= len(p.Conns) {
		idx = 0
	}
	p.Conns[idx].WriteTo(buf, ep.Addr)
	putEncode(buf)
}

func (p *Punch) readLoop(conn net.PacketConn, sockIdx int) {
	defer p.wg.Done()
	bufs := make([][]byte, readBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	for {
		batches, err := readBatch(conn, bufs)
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
			case PktRegister:
				continue
			case PktRegAck:
				if pkt.Dst != p.MyID {
					continue
				}
			}
			p.handle(pkt, bp.src, sockIdx)
		}
	}
}

func (p *Punch) handle(pkt *Packet, src net.Addr, sockIdx int) {
	ua, _ := src.(*net.UDPAddr)

	switch pkt.Type {
	case PktRegAck:
		return
	case PktRegister:
		return
	}

	ps := p.peer(pkt.Src)
	if ps == nil {
		return
	}
	ps.mu.Lock()
	ps.lastSeen = time.Now()
	switch pkt.Type {
	case PktProbe, PktProbe2:
		first, upgraded := ps.note(p, ua, sockIdx)
		transport := ps.transport
		ps.mu.Unlock()
		if first || upgraded {
			p.logf("peer %s: <- probe from %s -> connected via %s (socket %d)", pkt.Src.String()[:8], ua, transport, sockIdx)
		}
		ack := &Packet{Type: PktAck, Seq: pkt.Seq, Src: p.MyID, Dst: pkt.Src}
		buf := encodePooled(ack)
		p.Conns[sockIdx].WriteTo(buf, ua)
		putEncode(buf)
		p.report(ps, pkt.Src)
		return
	case PktAck:
		first, upgraded := ps.note(p, ua, sockIdx)
		transport := ps.transport
		ps.mu.Unlock()
		if first || upgraded {
			p.logf("peer %s: <- ack from %s -> connected via %s (socket %d)", pkt.Src.String()[:8], ua, transport, sockIdx)
		}
		p.report(ps, pkt.Src)
		return
	case PktData:
		first, upgraded := ps.note(p, ua, sockIdx)
		ps.mu.Unlock()
		if first || upgraded {
			p.report(ps, pkt.Src)
		}
		if p.OnData != nil {
			p.OnData(pkt.Src, pkt)
		}
	}
}

// note records the endpoint and socket a peer's packet arrived from and labels
// the link.
//
// A direct path, once confirmed, is never replaced by the relay: the relay
// keeps forwarding this peer's keepalives to the same socket, and letting
// those overwrite the endpoint would pull a punched link back onto the slow
// path every few seconds. Caller must hold ps.mu.
func (ps *peer) note(p *Punch, ua *net.UDPAddr, sockIdx int) (first, upgraded bool) {
	first = !ps.connected
	if ua == nil {
		return first, false
	}
	was := ps.transport
	ps.endpoint = ua
	ps.sockIdx = sockIdx
	ps.transport = StatePunched
	ps.connected = true
	// Pure P2P: any inbound packet from the peer confirms the direct punched
	// endpoint. "upgraded" marks the first transition into a punched link.
	upgraded = was != StatePunched
	return first, upgraded
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
