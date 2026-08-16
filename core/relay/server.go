// Package relay implements a lightweight TURN-style UDP relay over a single
// shared socket. Clients register with (room, token); the relay learns each
// member's address and broadcasts that member's packets to the other members
// of the same room. The socket can be multiplexed with STUN on one UDP port.
package relay

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"p2p/core/protocol"
	"p2p/core/punch"
)

// roomState is the per-room forwarding state.
type roomState struct {
	token      string
	tokens     map[string]string       // peerID -> per-peer relay token
	members    map[string]*net.UDPAddr // peerID -> learned address
	maxMembers int                     // 0 means unlimited
}

// Server forwards packets for all rooms over one UDP socket.
type Server struct {
	mu        sync.Mutex
	conn      *net.UDPConn
	owned     bool
	rooms     map[string]*roomState
	members   map[string]*roomState // peerID -> room (routing)
	regLogged map[string]bool       // throttle register logging
	// OnRegister, when set, is notified once per peer when it registers.
	// Useful for operators to confirm UDP relay traffic is arriving.
	OnRegister func(peerID, room string)
	// MaxRoomMembers limits relay members per room. 0 means unlimited.
	MaxRoomMembers int
	done           chan struct{}
	once           sync.Once
	wg             sync.WaitGroup
}

// NewServer creates a relay server.
func NewServer() *Server {
	return &Server{
		rooms:     make(map[string]*roomState),
		members:   make(map[string]*roomState),
		regLogged: make(map[string]bool),
		done:      make(chan struct{}),
	}
}

// UseConn hands the server an externally-owned UDP socket (e.g. one shared
// with STUN). The caller must deliver datagrams via Handle. The server will
// not close this socket on Close.
func (s *Server) UseConn(conn *net.UDPConn) *Server {
	s.mu.Lock()
	s.conn = conn
	s.owned = false
	s.mu.Unlock()
	return s
}

// Bind binds a UDP socket for standalone operation and starts the read loop.
func (s *Server) Bind(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.conn = conn
	s.owned = true
	s.mu.Unlock()
	s.wg.Add(1)
	go s.serve()
	return nil
}

// Allocate registers a room (creating the shared socket on demand) and
// returns the shared relay address "publicHost:port". The token gates
// membership.
func (s *Server) Allocate(room, token, publicHost string) (string, error) {
	if publicHost == "" {
		publicHost = "127.0.0.1"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rooms[room]; ok {
		return publicHost + ":" + s.portStr(), nil
	}
	if s.conn == nil {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(publicHost), Port: 0})
		if err != nil {
			// publicHost may not be directly bindable (e.g. NAT'd host):
			// fall back to any-address.
			conn, err = net.ListenUDP("udp", nil)
			if err != nil {
				return "", err
			}
		}
		s.conn = conn
		s.owned = true
		s.wg.Add(1)
		go s.serve()
	}
	s.rooms[room] = &roomState{token: token, tokens: make(map[string]string), members: make(map[string]*net.UDPAddr), maxMembers: s.MaxRoomMembers}
	return publicHost + ":" + s.portStr(), nil
}

// Grant records a per-peer relay token issued by the signaling server. A
// peer registering with this token is authenticated as that peer, preventing
// other room members from impersonating it through the relay.
func (s *Server) Grant(room, peerID, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.rooms[room]
	if rs == nil {
		return
	}
	if rs.tokens == nil {
		rs.tokens = make(map[string]string)
	}
	rs.tokens[peerID] = token
}

func (s *Server) portStr() string {
	if s.conn == nil {
		return "0"
	}
	if a, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		return fmt.Sprintf("%d", a.Port)
	}
	return "0"
}

func (s *Server) serve() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.Handle(src, buf[:n])
	}
}

// Handle processes one datagram received on the shared socket.
func (s *Server) Handle(src *net.UDPAddr, data []byte) {
	pkt, err := punch.Decode(data)
	if err != nil {
		return
	}
	srcID := pkt.Src.String()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return
	}
	if pkt.Type == punch.PktRegister {
		roomName, token := parseRegister(pkt.Payload)
		rs := s.rooms[roomName]
		if rs != nil && (rs.token == token || rs.tokens[srcID] == token) {
			if _, exists := rs.members[srcID]; !exists && rs.maxMembers > 0 && len(rs.members) >= rs.maxMembers {
				return
			}
			s.members[srcID] = rs
			rs.members[srcID] = src
			if s.OnRegister != nil && !s.regLogged[srcID] {
				s.regLogged[srcID] = true
				s.OnRegister(roomName, srcID)
			}
			ack := &punch.Packet{Type: punch.PktRegAck, Src: protocol.PeerID{}, Dst: pkt.Src}
			s.conn.WriteToUDP(punch.Encode(ack), src)
		}
		return
	}
	rs := s.members[srcID]
	if rs == nil {
		return
	}
	// refresh the learned address (matters for symmetric NATs)
	rs.members[srcID] = src
	// broadcast to the other members of the room
	var dst []*net.UDPAddr
	for id, addr := range rs.members {
		if id != srcID {
			dst = append(dst, addr)
		}
	}
	for _, a := range dst {
		s.conn.WriteToUDP(data, a)
	}
}

// parseRegister splits the register payload ("room\0token").
func parseRegister(p []byte) (room, token string) {
	if i := bytes.IndexByte(p, 0); i >= 0 {
		return string(p[:i]), string(p[i+1:])
	}
	return string(p), ""
}

// Close stops the relay. An externally-owned socket (UseConn) is left open.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		if s.owned && s.conn != nil {
			s.conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}
