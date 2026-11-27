// Package p2p is the application-facing SDK. It hides NAT detection, hole
// punching and signaling behind a simple connect/send/event API that is also
// bindable to Android via gomobile.
package p2p

// Config controls a Session. All addresses are "host:port" strings.
type Config struct {
	// ServerAddr is the single signaling server address ("host:port").
	ServerAddr string
	// STUNAddr is the primary STUN server address (defaults to ServerAddr).
	STUNAddr string
	// Token is an optional room secret required to join the room.
	Token string

	// AuthUser is an optional username for per-user server authentication.
	AuthUser string
	// AuthSecret is the shared secret (or the user's password when AuthUser
	// is set) used for mutual authentication with the server.
	AuthSecret string

	// PortPrediction enables symmetric-NAT port prediction.
	PortPrediction bool
	// EnableLAN allows same-LAN direct connections across all local interfaces.
	EnableLAN bool
	// EnableIPv6 attempts dual-stack IPv6 STUN discovery and direct punching.
	EnableIPv6 bool
	// EnableUPnP attempts NAT-PMP / PCP / UPnP IGD port mapping when available.
	EnableUPnP bool
	// Debug enables verbose hole-punching flow logs (delivered as EventDebug).
	Debug bool

	// TLS enables TLS for the signaling connection.
	TLS                   bool
	TLSServerName         string
	TLSInsecureSkipVerify bool

	// Plaintext disables data-plane encryption for performance testing.
	Plaintext bool

	// LegacyMesh keeps the retired mesh data plane for TUN traffic instead of
	// the WireGuard tunnel.
	LegacyMesh bool

	// TimeoutSec bounds the initial connection attempt (default 15).
	TimeoutSec int
	// ProbeIntervalMs is the delay between probe bursts (default 60).
	ProbeIntervalMs int
	// PunchTimeoutMs is kept for compatibility (default 4000).
	PunchTimeoutMs int
	// PredictionSockets is the number of UDP source sockets in the pool for
	// NAT4 plant/prediction legs (default 256).
	PredictionSockets int
	// PeerPortOffset shifts the deterministic block spray off the peer's
	// reported public port (default 20).
	PeerPortOffset int
	// SymmetricSpray is how many unique ports per round the easy side draws
	// without replacement toward a hard peer (default 512).
	SymmetricSpray int
	// SprayIPMax caps distinct public IPs sprayed per round when a peer
	// announces an inferred CGNAT PoolCIDR (default 64).
	SprayIPMax int
	// PunchPPS caps probe packet rate per second (default 1500).
	PunchPPS int
	// EscalateAfterMs is how long a soft/cone-classified peer may fail to
	// connect before escalating to hard plant+spray (default 2000).
	EscalateAfterMs int
	// STUNSecondaries is a comma-separated list of extra STUN observation
	// points merged with any STUN list pushed by the signaling server.
	STUNSecondaries string
}

// Defaults returns a Config tuned for pure-P2P NAT3<->NAT4 hole punching.
func Defaults() *Config {
	return &Config{
		PortPrediction:    true,
		EnableLAN:         true,
		EnableIPv6:        true,
		EnableUPnP:        true,
		TimeoutSec:        15,
		ProbeIntervalMs:   60,
		PunchTimeoutMs:    4000,
		PredictionSockets: 256,
		PeerPortOffset:    20,
		SymmetricSpray:    512,
		SprayIPMax:        64,
		PunchPPS:          1500,
		EscalateAfterMs:   2000,
	}
}

// applyDefaults fills in sensible defaults for zero-valued fields.
func (c *Config) applyDefaults() {
	if c == nil {
		return
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 15
	}
	if c.ProbeIntervalMs <= 0 {
		c.ProbeIntervalMs = 60
	}
	if c.PunchTimeoutMs <= 0 {
		c.PunchTimeoutMs = 4000
	}
	if c.SprayIPMax <= 0 {
		c.SprayIPMax = 64
	}
	if c.PunchPPS <= 0 {
		c.PunchPPS = 1500
	}
	if c.EscalateAfterMs <= 0 {
		c.EscalateAfterMs = 2000
	}
}
