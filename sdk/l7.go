package p2p

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// L7 is an optional application-layer API built on top of Session. It adds
// datagram, pub-sub and a reliable ordered message stream over the existing
// mesh datagram transport.
type L7 struct {
	sess *Session
	user Listener

	mu           sync.Mutex
	onDatagram   func(peerID string, data []byte)
	subs         map[string][]func(peerID string, data []byte)
	onStreamData func(peerID string, data []byte)
	recvStreams  map[string]*l7RecvStream
	streams      map[string]*L7Stream
	nextStreamID uint16

	pingMu       sync.Mutex
	pendingPings map[uint64]chan time.Duration
	nextPingID   uint64
}

const (
	l7Magic     = "P2PL7"
	l7Version   = 1
	l7HeaderLen = len(l7Magic) + 2

	l7Datagram   = 1
	l7PubSub     = 2
	l7StreamData = 3
	l7StreamAck  = 4
	l7Ping       = 5
	l7Pong       = 6
)

const l7RetransmitInterval = 200 * time.Millisecond

// NewL7 creates an L7 session that wraps a new Session. Events are forwarded
// to user (may be nil) after L7 messages have been handled.
func NewL7(cfg *Config, user Listener) (*L7, error) {
	l := &L7{
		user:         user,
		subs:         make(map[string][]func(peerID string, data []byte)),
		recvStreams:  make(map[string]*l7RecvStream),
		streams:      make(map[string]*L7Stream),
		pendingPings: make(map[uint64]chan time.Duration),
	}
	sess, err := NewSession(cfg, l)
	if err != nil {
		return nil, err
	}
	l.sess = sess
	return l, nil
}

// Session exposes the underlying Session.
func (l *L7) Session() *Session { return l.sess }

// Join joins a room/network.
func (l *L7) Join(room string) error { return l.sess.Connect(room) }

// Disconnect leaves the network and closes L7 resources.
func (l *L7) Disconnect() {
	l.mu.Lock()
	streams := make([]*L7Stream, 0, len(l.streams))
	for _, s := range l.streams {
		streams = append(streams, s)
	}
	l.mu.Unlock()
	for _, s := range streams {
		s.close()
	}
	l.sess.Disconnect()
}

// OnEvent implements Listener for the wrapped Session.
func (l *L7) OnEvent(event int, peerID string, data []byte) {
	if event == EventData && l.handleData(peerID, data) {
		return
	}
	if l.user != nil {
		l.user.OnEvent(event, peerID, data)
	}
}

func (l *L7) handleData(peerID string, data []byte) bool {
	kind, body, ok := l7Parse(data)
	if !ok {
		return false
	}
	switch kind {
	case l7Datagram:
		l.mu.Lock()
		cb := l.onDatagram
		l.mu.Unlock()
		if cb != nil {
			cb(peerID, body)
		}
	case l7PubSub:
		l.handlePubSub(peerID, body)
	case l7StreamData:
		l.handleStreamData(peerID, body)
	case l7StreamAck:
		l.handleStreamAck(peerID, body)
	case l7Ping:
		l.handlePing(peerID, body)
	case l7Pong:
		l.handlePong(peerID, body)
	}
	return true
}

// OnDatagram registers a handler for unreliable datagrams sent via
// SendDatagram.
func (l *L7) OnDatagram(handler func(peerID string, data []byte)) {
	l.mu.Lock()
	l.onDatagram = handler
	l.mu.Unlock()
}

// SendDatagram sends an unreliable message to one peer.
func (l *L7) SendDatagram(peerID string, data []byte) error {
	return l.sess.Send(peerID, l7Encode(l7Datagram, data))
}

// Subscribe registers a handler for a topic published via Publish.
func (l *L7) Subscribe(topic string, handler func(peerID string, data []byte)) {
	l.mu.Lock()
	l.subs[topic] = append(l.subs[topic], handler)
	l.mu.Unlock()
}

// Publish broadcasts a message to every node subscribed to topic.
func (l *L7) Publish(topic string, data []byte) error {
	if len(topic) > 65535 {
		return errors.New("l7: topic too long")
	}
	body := make([]byte, 2+len(topic)+len(data))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(topic)))
	copy(body[2:], topic)
	copy(body[2+len(topic):], data)
	return l.sess.Broadcast(l7Encode(l7PubSub, body))
}

func (l *L7) handlePubSub(peerID string, body []byte) {
	if len(body) < 2 {
		return
	}
	n := int(binary.BigEndian.Uint16(body[0:2]))
	if len(body) < 2+n {
		return
	}
	topic := string(body[2 : 2+n])
	payload := body[2+n:]
	l.mu.Lock()
	cbs := append([]func(peerID string, data []byte){}, l.subs[topic]...)
	l.mu.Unlock()
	for _, cb := range cbs {
		cb(peerID, payload)
	}
}

// OnStreamData registers a handler for reliable ordered stream messages
// received from any peer.
func (l *L7) OnStreamData(handler func(peerID string, data []byte)) {
	l.mu.Lock()
	l.onStreamData = handler
	l.mu.Unlock()
}

// OpenStream opens a reliable message stream to a peer.
func (l *L7) OpenStream(peerID string) *L7Stream {
	l.mu.Lock()
	l.nextStreamID++
	if l.nextStreamID == 0 {
		l.nextStreamID++
	}
	id := l.nextStreamID
	s := &L7Stream{
		l7:      l,
		peerID:  peerID,
		id:      id,
		unacked: make(map[uint32][]byte),
		done:    make(chan struct{}),
	}
	l.streams[streamKey(peerID, id)] = s
	l.mu.Unlock()
	return s
}

func (l *L7) handleStreamData(peerID string, body []byte) {
	if len(body) < 6 {
		return
	}
	streamID := binary.BigEndian.Uint16(body[0:2])
	seq := binary.BigEndian.Uint32(body[2:6])
	payload := body[6:]
	key := streamKey(peerID, streamID)

	// Always ack so the sender can stop retransmitting.
	ackBody := make([]byte, 6)
	binary.BigEndian.PutUint16(ackBody[0:2], streamID)
	binary.BigEndian.PutUint32(ackBody[2:6], seq)
	_ = l.sess.Send(peerID, l7Encode(l7StreamAck, ackBody))

	l.mu.Lock()
	rs := l.recvStreams[key]
	if rs == nil {
		rs = &l7RecvStream{nextSeq: 1, pending: make(map[uint32][]byte)}
		l.recvStreams[key] = rs
	}
	l.mu.Unlock()

	rs.mu.Lock()
	var deliver [][]byte
	if seq == rs.nextSeq {
		rs.nextSeq++
		deliver = append(deliver, payload)
		for {
			next, ok := rs.pending[rs.nextSeq]
			if !ok {
				break
			}
			delete(rs.pending, rs.nextSeq)
			rs.nextSeq++
			deliver = append(deliver, next)
		}
	} else if seq > rs.nextSeq {
		if _, dup := rs.pending[seq]; !dup {
			rs.pending[seq] = payload
		}
	}
	rs.mu.Unlock()

	l.mu.Lock()
	cb := l.onStreamData
	l.mu.Unlock()
	if cb == nil {
		return
	}
	for _, d := range deliver {
		cb(peerID, d)
	}
}

func (l *L7) handleStreamAck(peerID string, body []byte) {
	if len(body) < 6 {
		return
	}
	streamID := binary.BigEndian.Uint16(body[0:2])
	seq := binary.BigEndian.Uint32(body[2:6])
	key := streamKey(peerID, streamID)
	l.mu.Lock()
	s := l.streams[key]
	l.mu.Unlock()
	if s != nil {
		s.ack(seq)
	}
}

// Ping measures round-trip time to a peer using an L7 ping/pong exchange.
func (l *L7) Ping(peerID string, timeout time.Duration) (time.Duration, error) {
	l.pingMu.Lock()
	l.nextPingID++
	if l.nextPingID == 0 {
		l.nextPingID++
	}
	id := l.nextPingID
	ch := make(chan time.Duration, 1)
	l.pendingPings[id] = ch
	l.pingMu.Unlock()

	defer func() {
		l.pingMu.Lock()
		delete(l.pendingPings, id)
		l.pingMu.Unlock()
	}()

	sent := time.Now()
	body := make([]byte, 16)
	binary.BigEndian.PutUint64(body[0:8], uint64(sent.UnixNano()))
	binary.BigEndian.PutUint64(body[8:16], id)
	if err := l.sess.Send(peerID, l7Encode(l7Ping, body)); err != nil {
		return 0, err
	}

	select {
	case rtt := <-ch:
		return rtt, nil
	case <-time.After(timeout):
		return 0, errors.New("l7: ping timeout")
	}
}

// PingStats sends count pings and returns average RTT and packet loss ratio
// (0.0 = no loss, 1.0 = all lost).
func (l *L7) PingStats(peerID string, count int, interval time.Duration) (time.Duration, float64, error) {
	if count <= 0 {
		return 0, 0, errors.New("l7: count must be positive")
	}
	if interval <= 0 {
		interval = time.Second
	}
	var total time.Duration
	ok := 0
	for i := 0; i < count; i++ {
		rtt, err := l.Ping(peerID, interval)
		if err == nil {
			total += rtt
			ok++
		}
		if i < count-1 {
			time.Sleep(interval / 2)
		}
	}
	if ok == 0 {
		return 0, 1, nil
	}
	return total / time.Duration(ok), 1 - float64(ok)/float64(count), nil
}

func (l *L7) handlePing(peerID string, body []byte) {
	if len(body) < 16 {
		return
	}
	pong := make([]byte, 16)
	copy(pong, body)
	_ = l.sess.Send(peerID, l7Encode(l7Pong, pong))
}

func (l *L7) handlePong(peerID string, body []byte) {
	if len(body) < 16 {
		return
	}
	id := binary.BigEndian.Uint64(body[8:16])
	sentNanos := int64(binary.BigEndian.Uint64(body[0:8]))
	rtt := time.Since(time.Unix(0, sentNanos))
	l.pingMu.Lock()
	ch := l.pendingPings[id]
	delete(l.pendingPings, id)
	l.pingMu.Unlock()
	if ch != nil {
		ch <- rtt
	}
}

func streamKey(peerID string, id uint16) string {
	return fmt.Sprintf("%s|%d", peerID, id)
}

// l7RecvStream holds receiver-side ordering state for one stream.
type l7RecvStream struct {
	mu      sync.Mutex
	nextSeq uint32
	pending map[uint32][]byte
}

// L7Stream is a reliable ordered message stream to one peer.
type L7Stream struct {
	l7        *L7
	peerID    string
	id        uint16
	mu        sync.Mutex
	nextSeq   uint32
	unacked   map[uint32][]byte
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

// Send queues a message for reliable ordered delivery.
func (s *L7Stream) Send(data []byte) error {
	if s == nil {
		return errors.New("l7: nil stream")
	}
	s.mu.Lock()
	s.nextSeq++
	seq := s.nextSeq
	s.unacked[seq] = append([]byte(nil), data...)
	s.mu.Unlock()

	if err := s.sendData(seq, data); err != nil {
		return err
	}
	s.startRetransmit()
	return nil
}

func (s *L7Stream) sendData(seq uint32, data []byte) error {
	body := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(body[0:2], s.id)
	binary.BigEndian.PutUint32(body[2:6], seq)
	copy(body[6:], data)
	return s.l7.sess.Send(s.peerID, l7Encode(l7StreamData, body))
}

func (s *L7Stream) startRetransmit() {
	s.startOnce.Do(func() {
		go s.retransmitLoop()
	})
}

func (s *L7Stream) retransmitLoop() {
	ticker := time.NewTicker(l7RetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		s.mu.Lock()
		if len(s.unacked) == 0 {
			s.mu.Unlock()
			continue
		}
		type item struct {
			seq  uint32
			data []byte
		}
		items := make([]item, 0, len(s.unacked))
		for seq, data := range s.unacked {
			items = append(items, item{seq: seq, data: data})
		}
		s.mu.Unlock()
		for _, it := range items {
			_ = s.sendData(it.seq, it.data)
		}
	}
}

func (s *L7Stream) ack(seq uint32) {
	s.mu.Lock()
	delete(s.unacked, seq)
	s.mu.Unlock()
}

// Close stops retransmission and releases the stream handle.
func (s *L7Stream) Close() {
	if s != nil {
		s.close()
	}
}

func (s *L7Stream) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.l7.mu.Lock()
		delete(s.l7.streams, streamKey(s.peerID, s.id))
		s.l7.mu.Unlock()
	})
}

func l7Encode(kind byte, body []byte) []byte {
	buf := make([]byte, l7HeaderLen+len(body))
	copy(buf, l7Magic)
	buf[len(l7Magic)] = l7Version
	buf[len(l7Magic)+1] = kind
	copy(buf[l7HeaderLen:], body)
	return buf
}

func l7Parse(b []byte) (kind byte, body []byte, ok bool) {
	if len(b) < l7HeaderLen || string(b[:len(l7Magic)]) != l7Magic || b[len(l7Magic)] != l7Version {
		return 0, nil, false
	}
	return b[len(l7Magic)+1], b[l7HeaderLen:], true
}
