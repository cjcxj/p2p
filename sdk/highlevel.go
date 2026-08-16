package p2p

// This file provides the High-Level API layer from the roadmap (P4). It is a
// thin, developer-friendly wrapper over Session that hides lower-level details
// such as signaling, hole punching and mesh routing.

// HighLevel is the high-level P2P client facade.
type HighLevel struct {
	sess *Session
}

// Peer is a high-level view of a remote node.
type Peer struct {
	ID        string
	IP        string
	Connected bool
	Transport string
}

// Connection is a high-level handle to send data to one peer.
type Connection struct {
	id   string
	send func(peerID string, data []byte) error
}

// NewHighLevel creates a high-level client around a new Session.
func NewHighLevel(cfg *Config, l Listener) (*HighLevel, error) {
	s, err := NewSession(cfg, l)
	if err != nil {
		return nil, err
	}
	return &HighLevel{sess: s}, nil
}

// JoinNetwork joins a room/network asynchronously.
func (h *HighLevel) JoinNetwork(room string) error {
	return h.sess.Connect(room)
}

// Disconnect leaves the network and releases resources.
func (h *HighLevel) Disconnect() {
	h.sess.Disconnect()
}

// Peers returns the current member list.
func (h *HighLevel) Peers() []*Peer {
	members := h.sess.Members()
	out := make([]*Peer, 0, len(members))
	for _, m := range members {
		out = append(out, &Peer{
			ID:        m.PeerID,
			IP:        m.VirtualIP,
			Connected: m.Connected,
			Transport: m.Transport,
		})
	}
	return out
}

// Connect returns a high-level connection handle to a peer (by peer id or
// virtual IP).
func (h *HighLevel) Connect(peerID string) *Connection {
	return &Connection{id: peerID, send: h.sess.Send}
}

// SendTo sends data to a peer by id or virtual IP.
func (h *HighLevel) SendTo(peerID string, data []byte) error {
	return h.sess.Send(peerID, data)
}

// SendToIP sends data to a virtual IP (auto multi-hop).
func (h *HighLevel) SendToIP(ip string, data []byte) error {
	return h.sess.SendToIP(ip, data)
}

// Broadcast sends data to every peer in the network.
func (h *HighLevel) Broadcast(data []byte) error {
	return h.sess.Broadcast(data)
}

// LocalIP returns this node's virtual IP.
func (h *HighLevel) LocalIP() string {
	return h.sess.LocalIP()
}

// Subnet returns the virtual subnet.
func (h *HighLevel) Subnet() string {
	return h.sess.Subnet()
}

// Session exposes the underlying low-level Session for callers that need the
// full SDK API.
func (h *HighLevel) Session() *Session {
	return h.sess
}

// Send writes data to the peer this connection is bound to.
func (c *Connection) Send(data []byte) error {
	if c == nil || c.send == nil {
		return errBadIP
	}
	return c.send(c.id, data)
}
