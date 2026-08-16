package signaling

import (
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"p2p/core/auth"
	"p2p/core/protocol"
)

// DefaultNetwork is the virtual subnet used when Options.Network is empty.
const DefaultNetwork = "10.9.0.0/24"

// Server is the signaling TCP server.
type Server struct {
	ln            net.Listener
	hub           *Hub
	relayAlloc    func(roomID, token string) (addr string, err error)
	relayGrant    func(roomID, peerID, token string)
	network       *net.IPNet
	auth          *authConfig
	mu            sync.Mutex
	conns         map[net.Conn]struct{}
	connIPs       map[string]int
	lastSeen      map[net.Conn]time.Time
	maxConnsPerIP int
	wg            sync.WaitGroup
	done          chan struct{}
	once          sync.Once
}

// idleTimeout is how long a member may stay silent before the server reaps
// its connection (frees its virtual address). Clients heartbeat every 25s.
const idleTimeout = 75 * time.Second

// Options configures the server.
type Options struct {
	// RelayAlloc allocates a relay socket for a room on demand, gated by the
	// room token. Optional.
	RelayAlloc func(roomID, token string) (addr string, err error)
	// RelayGrant, when set, records a per-peer relay token so the relay can
	// authenticate a specific peer instead of only checking the room token.
	RelayGrant func(roomID, peerID, token string)
	// Logger receives operational messages; nil disables logging.
	Logger *log.Logger
	// Network is the virtual subnet for per-room address allocation.
	// Empty defaults to DefaultNetwork. Set to "0.0.0.0/0" to disable
	// virtual IP assignment.
	Network string
	// Secret is a service-level pre-shared key. When set (or Users is set),
	// every signaling connection must complete the mutual auth handshake.
	Secret string
	// Users maps username -> password for per-user authentication. When set,
	// the client must present a valid username and password.
	Users map[string]string
	// MaxConnsPerIP limits concurrent signaling connections per source IP.
	// 0 means unlimited.
	MaxConnsPerIP int
	// MaxRoomMembers limits members per room. 0 means unlimited.
	MaxRoomMembers int
	// TLSConfig, when set, makes the signaling listener serve TLS.
	TLSConfig *tls.Config
}

// NewServer listens on addr and serves signaling.
func NewServer(addr string, opts Options) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if opts.TLSConfig != nil {
		ln = tls.NewListener(ln, opts.TLSConfig)
	}
	network := opts.Network
	if network == "" {
		network = DefaultNetwork
	}
	var ipnet *net.IPNet
	if network != "0.0.0.0/0" {
		if _, ipnet, err = net.ParseCIDR(network); err != nil {
			ln.Close()
			return nil, err
		}
	}
	s := &Server{
		ln:            ln,
		hub:           NewHub(),
		relayAlloc:    opts.RelayAlloc,
		relayGrant:    opts.RelayGrant,
		network:       ipnet,
		conns:         make(map[net.Conn]struct{}),
		connIPs:       make(map[string]int),
		lastSeen:      make(map[net.Conn]time.Time),
		maxConnsPerIP: opts.MaxConnsPerIP,
		done:          make(chan struct{}),
	}
	if opts.MaxRoomMembers > 0 {
		s.hub.SetMaxMembers(opts.MaxRoomMembers)
	}
	if opts.Secret != "" || len(opts.Users) > 0 {
		s.auth = newAuthConfig(opts.Secret, opts.Users)
	}
	s.wg.Add(1)
	go s.acceptLoop()
	s.wg.Add(1)
	go s.reapLoop()
	return s, nil
}

// reapLoop closes member connections that have been silent too long, so
// crashed/half-open clients release their virtual addresses and rooms stay
// clean.
func (s *Server) reapLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for c, last := range s.lastSeen {
				if now.Sub(last) > idleTimeout {
					c.Close()
				}
			}
			s.mu.Unlock()
		}
	}
}

// Network returns the configured virtual subnet.
func (s *Server) Network() string {
	if s.network == nil {
		return ""
	}
	return s.network.String()
}

// Addr returns the listen address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// handleConn runs the per-connection state machine.
func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	ip := remoteIP(conn)
	if ip != "" && s.maxConnsPerIP > 0 {
		s.mu.Lock()
		if s.connIPs[ip] >= s.maxConnsPerIP {
			s.mu.Unlock()
			s.fail(conn, "too many connections from this IP")
			return
		}
		s.connIPs[ip]++
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.connIPs[ip]--
			if s.connIPs[ip] == 0 {
				delete(s.connIPs, ip)
			}
			s.mu.Unlock()
		}()
	}
	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		delete(s.lastSeen, conn)
		s.mu.Unlock()
	}()

	// First frame must be a hello.
	hello, err := ReadMsg(conn)
	if err != nil || hello.Type != protocol.MsgHello {
		s.fail(conn, "expected hello")
		return
	}
	// Mutual authentication handshake (server auth + client auth).
	if s.auth != nil {
		if !s.authenticate(conn, hello) {
			return
		}
	}
	s.touch(conn)
	id := protocol.NewPeerID()
	roomID := hello.Room
	token := hello.Token

	mem := &member{id: id, conn: conn}

	// Allocate a relay socket for the room if enabled.
	relayAddr := ""
	relayToken := ""
	if s.relayAlloc != nil {
		if ra, err := s.relayAlloc(roomID, token); err == nil {
			relayAddr = ra
			relayToken = auth.RandomNonce()
			if s.relayGrant != nil {
				s.relayGrant(roomID, id.String(), relayToken)
			}
		}
	}

	vip, _, err := s.hub.join(roomID, token, mem, relayAddr, s.network)
	if err != nil {
		s.fail(conn, err.Error())
		return
	}

	// All writes to a member's conn go through member.mu to avoid concurrent
	// frame interleaving with broadcast/forward goroutines.
	members := s.hub.membersInfo(roomID)
	mem.mu.Lock()
	WriteMsg(conn, protocol.Message{Type: protocol.MsgWelcome, PeerID: id.String(), VirtualIP: vip, Network: s.Network()})
	if relayAddr != "" {
		WriteMsg(conn, protocol.Message{Type: protocol.MsgRelayGrant, RelayAddr: relayAddr, RelayToken: relayToken})
	}
	WriteMsg(conn, protocol.Message{Type: protocol.MsgMembers, Members: members})
	mem.mu.Unlock()
	// Announce the full member list to everyone else.
	s.hub.broadcast(roomID, id, protocol.Message{Type: protocol.MsgMembers, Members: members})

	for {
		msg, err := ReadMsg(conn)
		if err != nil {
			break
		}
		s.touch(conn)
		switch msg.Type {
		case protocol.MsgCandidate:
			if msg.Candidate == nil {
				continue
			}
			// forward the candidate to the targeted peer
			tid, err := protocol.ParsePeerID(msg.Candidate.PeerID)
			if err != nil {
				continue
			}
			s.hub.sendTo(roomID, tid, msg)
		case protocol.MsgPing:
			// heartbeat: keep-alive, nothing to do
		case protocol.MsgLeave:
			goto done
		default:
			// ignore unknown frames
		}
	}
done:
	s.hub.freeOnLeave(roomID, id)
	s.hub.leave(roomID, id)
	s.hub.broadcast(roomID, id, protocol.Message{Type: protocol.MsgMembers, Members: s.hub.membersInfo(roomID)})
}

func remoteIP(conn net.Conn) string {
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return ""
}

func (s *Server) fail(conn net.Conn, reason string) {
	WriteMsg(conn, protocol.Message{Type: protocol.MsgError, Error: reason})
}

// touch records that a connection is alive.
func (s *Server) touch(conn net.Conn) {
	s.mu.Lock()
	s.lastSeen[conn] = time.Now()
	s.mu.Unlock()
}

// authConfig holds the server's credential material. credKeys maps username
// to the derived HMAC key; when Users is empty, secret is a shared PSK.
type authConfig struct {
	secret   string
	credKeys map[string][]byte // user -> derived key
}

func newAuthConfig(secret string, users map[string]string) *authConfig {
	a := &authConfig{secret: secret}
	if len(users) > 0 {
		a.credKeys = make(map[string][]byte, len(users))
		for u, p := range users {
			a.credKeys[u] = auth.CredKey(p, u)
		}
	}
	return a
}

// keyFor returns the credential key for a user, or nil when unauthorised.
func (a *authConfig) keyFor(user string) []byte {
	if a.credKeys != nil {
		return a.credKeys[user]
	}
	if a.secret != "" {
		return auth.CredKey(a.secret, user)
	}
	return nil
}

// authenticate runs the mutual handshake: the server proves it knows the
// shared credential (client auth) and requires the client to prove it too
// (server auth). Returns false (closing the connection) on failure.
func (s *Server) authenticate(conn net.Conn, hello protocol.Message) bool {
	clientNonce := hello.Nonce
	key := s.auth.keyFor(hello.User)
	if key == nil {
		s.fail(conn, "unauthorized")
		return false
	}
	serverNonce := auth.RandomNonce()
	if err := WriteMsg(conn, protocol.Message{Type: protocol.MsgChallenge, Nonce: serverNonce}); err != nil {
		return false
	}
	authMsg, err := ReadMsg(conn)
	if err != nil || authMsg.Type != protocol.MsgAuth {
		s.fail(conn, "authentication required")
		return false
	}
	want := auth.Proof(key, "client", clientNonce, serverNonce)
	if !auth.Equal(authMsg.Proof, want) {
		s.fail(conn, "invalid credentials")
		return false
	}
	proof := auth.Proof(key, "server", serverNonce, clientNonce)
	return WriteMsg(conn, protocol.Message{Type: protocol.MsgAuthOK, Proof: proof}) == nil
}

// Close shuts the server down.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}
