package p2p

import (
	"encoding/hex"
	"errors"
	"net"

	"golang.zx2c4.com/wireguard/tun"

	"p2p/core/punch"
	"p2p/core/tundev"
	"p2p/wgengine"
)

// wireTunnel connects a tunnel to the live punch engine in both directions:
// inbound WireGuard frames arrive from every pool socket through the ingress
// hook, and outbound frames leave through the socket that actually punched each
// peer. The second half is what lets the tunnel ride a hole punched on a
// non-primary socket -- sending a reply out a different socket would use a
// source the peer's NAT never mapped and silently drop the handshake.
func wireTunnel(t *wgengine.Tunnel, ph *punch.Punch) {
	t.SetOutboundRouter(ph.SendWireGuard)
	ph.SetWireGuardSink(t.Bind().Ingest)
}

// tunnelPeer is one WireGuard peer entry, assembled from what the punching
// already produced: a reachable endpoint and the peer's advertised X25519 key.
type tunnelPeer struct {
	id        string
	pub       string
	endpoint  string
	vip       string
	initiator bool
}

// wgPrivateHex renders this session's X25519 private key in the shape
// WireGuard's configuration interface expects. The tunnel reuses the key the
// signaling candidate already advertises, so no protocol field is needed for
// the far side to know it. It is the same key the legacy per-packet AEAD is
// derived from until that path is removed.
func (s *Session) wgPrivateHex() (string, error) {
	s.mu.Lock()
	key := s.x25519
	s.mu.Unlock()
	if key == nil {
		return "", errors.New("p2p: no session key")
	}
	return hex.EncodeToString(key.Bytes()), nil
}

// OpenTUN creates this session's virtual network interface and carries its
// traffic through a WireGuard tunnel on the hole-punched UDP socket. Call it
// after Connect, once LocalIP is set. The session owns the interface and
// closes it on Disconnect.
//
// Desktop only: it needs administrator/root and, on Windows, wintun.dll next
// to the executable. On Android the interface comes from VpnService, so use
// AttachTUN with its file descriptor instead.
func (s *Session) OpenTUN(mtu int) error {
	s.mu.Lock()
	if s.cfg.LegacyMesh {
		s.mu.Unlock()
		return errors.New("p2p: OpenTUN needs the WireGuard data plane (Config.LegacyMesh is set)")
	}
	if s.tunnel != nil || s.tunFile != nil {
		s.mu.Unlock()
		return errors.New("p2p: tun already attached")
	}
	vip, ipnet := s.vip, s.ipnet
	s.mu.Unlock()
	if vip == nil || ipnet == nil {
		return errors.New("p2p: session not ready (no virtual address)")
	}
	dev, err := tundev.Create(vip, ipnet.Mask, mtu)
	if err != nil {
		return err
	}
	return s.startTunnel(dev.TUN(), dev.Name())
}

// TUNName returns the OS name of the interface OpenTUN created, or the name of
// the attached descriptor. Empty when no tunnel is running.
func (s *Session) TUNName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnelName
}

// startTunnel brings the WireGuard interface up over the session's UDP socket
// and takes ownership of dev. It is the point where the two data planes part:
// IP packets now travel as WireGuard frames on the socket the punch engine
// reads, separated from punch frames by their leading byte.
func (s *Session) startTunnel(dev tun.Device, name string) error {
	priv, err := s.wgPrivateHex()
	if err != nil {
		dev.Close()
		return err
	}
	t := wgengine.New(dev, s.conn, s.cfg.Debug)
	if err := t.Start(priv); err != nil {
		t.Stop()
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		t.Stop()
		return net.ErrClosed
	}
	s.tunnel = t
	s.tunnelName = name
	ph := s.ph
	s.mu.Unlock()
	if ph != nil {
		wireTunnel(t, ph)
	}
	s.applyTunnelPeers(s.pendingTunnelPeers())
	if s.cfg.Debug {
		// Handshake state is the first thing to look at when an interface is up
		// but carries nothing, and on a phone the log is the only way to see it.
		s.debugf("p2p: wireguard interface " + name + ":\n" + t.Dump())
	}
	return nil
}

// pendingTunnelPeers lists the peers the tunnel can carry right now. Relay
// links are excluded: WireGuard writes its frames straight to the endpoint,
// and a relay only forwards its own framing.
func (s *Session) pendingTunnelPeers() []tunnelPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel == nil {
		return nil
	}
	out := make([]tunnelPeer, 0, len(s.peers))
	for id, r := range s.peers {
		if tp, ok := s.tunnelPeer(id, r); ok {
			out = append(out, tp)
		}
	}
	return out
}

// tunnelPeer reports the tunnel entry a peer needs. Caller holds s.mu.
func (s *Session) tunnelPeer(id string, r *remote) (tunnelPeer, bool) {
	if r == nil || !r.connected || r.wgPub == "" || r.endpoint == "" || r.vip == nil {
		return tunnelPeer{}, false
	}
	// Nothing to do while the configured endpoint is the one in use.
	if r.wgEndpoint == r.endpoint {
		return tunnelPeer{}, false
	}
	return tunnelPeer{
		id:       id,
		pub:      r.wgPub,
		endpoint: r.endpoint,
		vip:      r.vip.String(),
		// Both sides can derive the same election from the two peer ids, so
		// exactly one of them starts the handshake instead of the two
		// destroying each other's pending initiation.
		initiator: s.id.Less(r.id),
	}, true
}

// applyTunnelPeers installs peer entries and remembers which endpoint each one
// was configured for.
func (s *Session) applyTunnelPeers(list []tunnelPeer) {
	if len(list) == 0 {
		return
	}
	s.mu.Lock()
	t := s.tunnel
	s.mu.Unlock()
	if t == nil {
		return
	}
	for _, tp := range list {
		if err := t.AddPeer(tp.pub, tp.endpoint, tp.vip, tp.initiator); err != nil {
			s.debugf("p2p: wireguard peer " + tp.id + ": " + err.Error())
			continue
		}
		s.mu.Lock()
		if r := s.peers[tp.id]; r != nil && r.wgPub == tp.pub {
			r.wgEndpoint = tp.endpoint
		}
		s.mu.Unlock()
	}
}

// dropTunnelPeer removes a peer that left or lost its direct path.
func (s *Session) dropTunnelPeer(pub, endpoint string) {
	if pub == "" || endpoint == "" {
		return
	}
	s.mu.Lock()
	t := s.tunnel
	s.mu.Unlock()
	if t == nil {
		return
	}
	if err := t.RemovePeer(pub); err != nil {
		s.debugf("p2p: wireguard remove: " + err.Error())
	}
}

// CloseTUN tears the tunnel down and leaves the session running: the room
// membership, the punched socket and the NAT mappings all survive, so turning
// a phone's VPN interface off does not mean having to re-punch to turn it back
// on. Calling it with no tunnel attached does nothing.
func (s *Session) CloseTUN() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	tun := s.tunnel
	tf := s.tunFile
	stop := s.tunWriteStop
	ph := s.ph
	s.tunnel = nil
	s.tunnelName = ""
	s.tunFile = nil
	s.tunWriteCh = nil
	s.tunWriteStop = nil
	// Forget which endpoint each peer was configured for. A later attach builds
	// a fresh device, and every peer has to be installed into that one.
	for _, r := range s.peers {
		r.wgEndpoint = ""
	}
	s.mu.Unlock()

	if ph != nil {
		ph.SetWireGuardSink(nil)
	}
	// The tunnel stops before its descriptor is released; the device's read
	// loop owns the fd until then.
	if tun != nil {
		tun.Stop()
	}
	if stop != nil {
		close(stop)
	}
	if tf != nil {
		_ = tf.Close()
	}
}
