package signaling

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"p2p/core/auth"
	"p2p/core/protocol"
)

// Auth carries the client's credential for the mutual auth handshake. Secret
// is a pre-shared key or, when User is set, the user's password.
type Auth struct {
	User   string
	Secret string
}

// Client is a signaling connection.
type Client struct {
	conn net.Conn

	mu      sync.Mutex
	peerID  protocol.PeerID
	vip     string
	network string
	// stunServers is the observation-point list the server pushed in MsgWelcome;
	// one deployment configures it once instead of every client repeating flags.
	stunServers []string
	closed      bool

	// OnMessage is invoked from the read goroutine for each inbound frame.
	OnMessage func(protocol.Message) error
	// OnClose is invoked once when the connection ends.
	OnClose func(err error)
}

// Dial connects to a signaling server over plain TCP and performs the hello
// (and, when auth is provided, the mutual authentication) handshake.
func Dial(addr, room, token string, a *Auth) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return handshake(conn, room, token, a)
}

// DialTLS connects to a signaling server over TLS and performs the same
// handshake. The caller supplies the client TLS configuration (ServerName,
// root CAs, InsecureSkipVerify, etc.).
func DialTLS(addr, room, token string, a *Auth, cfg *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return handshake(conn, room, token, a)
}

func handshake(conn net.Conn, room, token string, a *Auth) (*Client, error) {
	c := &Client{conn: conn}

	hello := protocol.Message{
		Type:  protocol.MsgHello,
		Room:  room,
		Token: token,
	}
	clientNonce := ""
	didAuth := false
	if a != nil {
		clientNonce = auth.RandomNonce()
		hello.User = a.User
		hello.Nonce = clientNonce
	}
	if err := WriteMsg(conn, hello); err != nil {
		conn.Close()
		return nil, err
	}

	for {
		m, err := ReadMsg(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		switch m.Type {
		case protocol.MsgChallenge:
			if a == nil {
				conn.Close()
				return nil, errors.New("signaling: server requires authentication")
			}
			// client proves itself to the server
			key := auth.CredKey(a.Secret, a.User)
			serverNonce := m.Nonce
			proof := auth.Proof(key, "client", clientNonce, serverNonce)
			if err := WriteMsg(conn, protocol.Message{Type: protocol.MsgAuth, User: a.User, Proof: proof}); err != nil {
				conn.Close()
				return nil, err
			}
			// server proves itself to the client
			ok, err := ReadMsg(conn)
			if err != nil {
				conn.Close()
				return nil, err
			}
			if ok.Type != protocol.MsgAuthOK {
				conn.Close()
				return nil, &ServerError{"authentication failed"}
			}
			want := auth.Proof(key, "server", serverNonce, clientNonce)
			if !auth.Equal(ok.Proof, want) {
				conn.Close()
				return nil, errors.New("signaling: server authentication failed")
			}
			didAuth = true
		case protocol.MsgWelcome:
			if a != nil && !didAuth {
				// client configured auth but the server never challenged:
				// refuse to talk to a server that cannot prove itself
				conn.Close()
				return nil, errors.New("signaling: server does not require authentication")
			}
			id, err := protocol.ParsePeerID(m.PeerID)
			if err != nil {
				conn.Close()
				return nil, err
			}
			c.peerID = id
			c.vip = m.VirtualIP
			c.network = m.Network
			if len(m.STUNServers) > 0 {
				c.stunServers = append([]string(nil), m.STUNServers...)
			}
			return c, nil
		case protocol.MsgError:
			conn.Close()
			return nil, &ServerError{m.Error}
		}
	}
}

// ServerError reports a signaling-side rejection.
type ServerError struct{ Reason string }

func (e *ServerError) Error() string { return "signaling: " + e.Reason }

// PeerID returns the identifier assigned by the server.
func (c *Client) PeerID() protocol.PeerID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerID
}

// VirtualIP returns the virtual address assigned by the server (may be empty
// when the server does not allocate addresses).
func (c *Client) VirtualIP() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vip
}

// Network returns the room's virtual subnet (may be empty).
func (c *Client) Network() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.network
}

// STUNServers returns the STUN observation points the signaling server advertised,
// or nil when it advertises none. Copied so a caller cannot mutate client state.
func (c *Client) STUNServers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stunServers) == 0 {
		return nil
	}
	return append([]string(nil), c.stunServers...)
}

// Send writes a message.
func (c *Client) Send(m protocol.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	return WriteMsg(c.conn, m)
}

// Run starts the read loop; blocks until the connection closes.
func (c *Client) Run() {
	// periodic heartbeat so the server can reap us if the TCP half-opens
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-heartbeat.C:
				if err := c.Send(protocol.Message{Type: protocol.MsgPing}); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()
	for {
		m, err := ReadMsg(c.conn)
		if err != nil {
			c.Close()
			if c.OnClose != nil {
				c.OnClose(err)
			}
			return
		}
		if c.OnMessage != nil {
			if err := c.OnMessage(m); err != nil {
				c.Close()
				if c.OnClose != nil {
					c.OnClose(err)
				}
				return
			}
		}
	}
}

// Close terminates the connection.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.conn.Close()
	c.mu.Unlock()
}
