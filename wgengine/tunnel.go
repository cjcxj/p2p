package wgengine

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// handshakeRetryEvery is how long the initiator waits before reopening a
// handshake that the responder never answered. WireGuard itself stays quiet for
// five seconds after an initiation, so without this a peer that finished
// configuring a moment too late costs the link five seconds of dead air.
const (
	handshakeRetryEvery = 600 * time.Millisecond
	handshakeRetries    = 4
)

// peerSpec is the configuration a tunnel entry was last asked to hold. The
// handshake-retry loop compares against it so it can never re-write a peer from
// a copy that a newer AddPeer has already superseded.
type peerSpec struct {
	endpoint  string
	vip       string
	initiator bool
}

// Tunnel is a WireGuard interface whose UDP transport is the socket the punch
// engine already owns. Peers are added only once hole punching has produced a
// reachable endpoint.
type Tunnel struct {
	dev    *device.Device
	bind   *Bind
	tunDev tun.Device

	done sync.Once
	fin  chan struct{}

	mu    sync.Mutex
	specs map[string]peerSpec
}

// New wraps tunDev and pc. pc must be the same socket passed to punch.New.
func New(tunDev tun.Device, pc net.PacketConn, verbose bool) *Tunnel {
	level := device.LogLevelSilent
	if verbose {
		level = device.LogLevelVerbose
	}
	bind := NewBind(pc)
	return &Tunnel{
		dev:    device.NewDevice(tunDev, bind, device.NewLogger(level, "p2p-wg ")),
		bind:   bind,
		tunDev: tunDev,
		fin:    make(chan struct{}),
		specs:  make(map[string]peerSpec),
	}
}

// Bind exposes the ingress hook the punch read loop feeds WireGuard packets to.
func (t *Tunnel) Bind() *Bind { return t.bind }

// SetOutboundRouter makes the tunnel write each datagram through a caller
// supplied function instead of its fixed socket. The session installs one that
// selects the punch engine's winning socket per peer, so the WireGuard data
// plane shares the exact NAT mapping hole punching opened rather than a
// different socket's unmapped source.
func (t *Tunnel) SetOutboundRouter(fn func([]byte, *net.UDPAddr) error) {
	t.bind.SetSender(fn)
}

// Start installs the local private key and brings the interface up. The listen
// port is deliberately not set: the socket is already bound by the punch
// engine, and re-binding would lose the NAT mapping hole punching created.
func (t *Tunnel) Start(privateHex string) error {
	if err := t.dev.IpcSet("private_key=" + privateHex + "\n"); err != nil {
		return err
	}
	if err := t.dev.Up(); err != nil {
		return err
	}
	return nil
}

// AddPeer configures a punched peer. pubHex is the peer's X25519 public key --
// the same value already carried in Candidate.X25519Pub, hex -- endpoint is the
// address punching made reachable, and vip the peer's virtual address.
//
// Exactly one side passes initiator=true. Setting the keepalive interval makes
// wireguard-go emit a packet for the peer straight away, which becomes a
// handshake initiation because no session exists yet. If both sides did that at
// the same instant they would destroy each other's pending initiation -- a peer
// holds a single handshake slot -- and the tunnel would only come up on the
// retransmit five seconds later. The responder therefore stays silent and merely
// answers. The punch engine already refreshes the NAT mapping on its own, so the
// initiator is the only side that needs WireGuard's keepalive.
func (t *Tunnel) AddPeer(pubHex, endpoint, vip string, initiator bool) error {
	if err := t.addPeer(pubHex, endpoint, vip, initiator); err != nil {
		return err
	}
	// An initiation that arrived before this peer existed was dropped by the
	// device; feed it back so the responder answers now instead of waiting out
	// WireGuard's five second retry.
	t.bind.ReplayInitiation(endpoint)
	if initiator {
		go t.recoverHandshake(pubHex, endpoint, vip)
	}
	return nil
}

func (t *Tunnel) addPeer(pubHex, endpoint, vip string, kick bool) error {
	keepalive := ""
	if kick {
		keepalive = "\npersistent_keepalive_interval=25"
	}
	if err := t.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\nendpoint=%s%s\nallowed_ip=%s/32\n",
		pubHex, endpoint, keepalive, vip)); err != nil {
		return err
	}
	t.mu.Lock()
	t.specs[pubHex] = peerSpec{endpoint: endpoint, vip: vip, initiator: kick}
	t.mu.Unlock()
	return nil
}

// spec reports the configuration this tunnel was last asked to hold for pubHex.
func (t *Tunnel) spec(pubHex string) (peerSpec, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.specs[pubHex]
	return s, ok
}

// recoverHandshake re-opens the handshake until the responder has answered.
// Losing the first initiation is the normal race of two peers that finished
// punching a few milliseconds apart: the initiation can arrive before the far
// side had the peer configured, and WireGuard then refuses to send another for
// five seconds. Dropping and re-adding the peer resets that guard.
func (t *Tunnel) recoverHandshake(pubHex, endpoint, vip string) {
	for i := 0; i < handshakeRetries; i++ {
		select {
		case <-time.After(handshakeRetryEvery):
		case <-t.fin:
			return
		}
		if t.handshook(pubHex) {
			return
		}
		// A newer AddPeer -- the peer roamed, or it rejoined under this same key
		// after reconnecting -- owns the entry now. Re-writing the captured
		// address would point the tunnel back at a path that is already dead,
		// and the session would keep believing the newer one was installed.
		cur, ok := t.spec(pubHex)
		if !ok || cur.endpoint != endpoint || cur.vip != vip {
			return
		}
		if err := t.RemovePeer(pubHex); err != nil {
			return
		}
		if err := t.addPeer(pubHex, endpoint, vip, true); err != nil {
			return
		}
	}
}

// handshook reports whether the peer completed a Noise handshake.
func (t *Tunnel) handshook(pubHex string) bool {
	var buf bytes.Buffer
	if err := t.dev.IpcGetOperation(&buf); err != nil {
		return true
	}
	mine := false
	for _, line := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "public_key="):
			mine = line == "public_key="+pubHex
		case mine && strings.HasPrefix(line, "last_handshake_time_sec="):
			return line != "last_handshake_time_sec=0"
		}
	}
	return true
}

// RemovePeer drops a peer that has left the room.
func (t *Tunnel) RemovePeer(pubHex string) error {
	t.mu.Lock()
	spec, known := t.specs[pubHex]
	t.mu.Unlock()

	err := t.dev.IpcSet("public_key=" + pubHex + "\nremove=true\n")
	if err == nil {
		t.mu.Lock()
		delete(t.specs, pubHex)
		t.mu.Unlock()
		if known && spec.endpoint != "" {
			// Any initiation cached for this path belongs to a peer that no longer
			// exists. A rejoining peer under a new key must not be answered with
			// the old one, whose anti-replay state is already spent.
			t.bind.ForgetInitiation(spec.endpoint)
		}
	}
	return err
}

// Stop tears the interface down and releases the bind and tun devices.
func (t *Tunnel) Stop() {
	t.done.Do(func() { close(t.fin) })
	t.dev.Close()
	t.bind.Close()
	if t.tunDev != nil {
		t.tunDev.Close()
	}
}

// Dump returns the configuration view WireGuard keeps for this interface. It is
// a debugging aid: handshake state is the first thing to look at when a tunnel
// carries nothing. Secret material is redacted -- on a phone this text lands in
// the app's own log page, where the user can copy it out.
func (t *Tunnel) Dump() string {
	var buf bytes.Buffer
	if err := t.dev.IpcGetOperation(&buf); err != nil {
		return "dump: " + err.Error()
	}
	return redactSecrets(buf.String())
}

var secretKeys = []string{"private_key=", "preshared_key="}

func redactSecrets(dump string) string {
	lines := strings.Split(dump, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		for _, key := range secretKeys {
			if rest := strings.TrimPrefix(trimmed, key); rest != trimmed {
				lines[i] = line[:len(line)-len(trimmed)] + key + "(redacted)"
			}
		}
	}
	return strings.Join(lines, "\n")
}
