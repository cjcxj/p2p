// Package p2p is the application-facing SDK. It hides NAT detection, hole
// punching, signaling and relay fallback behind a small connect/send/event
// API that is also bindable to Android via gomobile.
package p2p

// Config controls a Session. All addresses are "host:port" strings.
type Config struct {
	// ServerAddr is the signaling server address.
	ServerAddr string
	// STUNAddr is the STUN server address used for NAT detection.
	STUNAddr string
	// Token is an optional room secret required to join the room.
	Token string

	// AuthUser is an optional username for per-user server authentication.
	AuthUser string
	// AuthSecret is the shared secret (or the user's password when AuthUser
	// is set) used for mutual authentication with the server. When empty the
	// client connects to an open server.
	AuthSecret string

	// PortPrediction enables symmetric-NAT port prediction.
	PortPrediction bool
	// EnableLAN allows same-LAN direct connections.
	EnableLAN bool
	// Debug enables verbose hole-punching flow logs (delivered as
	// EventDebug).
	Debug bool

	// TLS enables TLS for the signaling connection. TLSServerName and
	// TLSInsecureSkipVerify configure the client TLS handshake.
	TLS bool
	// TLSServerName overrides the TLS ServerName (usually the DNS name in
	// the server certificate).
	TLSServerName string
	// TLSInsecureSkipVerify disables certificate verification. Intended for
	// self-signed certificates in trusted/internal deployments only.
	TLSInsecureSkipVerify bool

	// Plaintext disables data-plane encryption for performance testing. Both
	// ends must set it; traffic will not be encrypted end-to-end.
	Plaintext bool

	// LegacyMesh keeps the retired mesh data plane for TUN traffic instead of
	// the WireGuard tunnel. It exists only to A/B the two paths on real
	// hardware and mobile; leave it false unless comparing.
	LegacyMesh bool

	// TimeoutSec bounds the whole connection attempt (default 15).
	TimeoutSec int
	// ProbeIntervalMs is the delay between probe bursts (default 200).
	ProbeIntervalMs int
	// PunchTimeoutMs is how long to punch before falling back to relay
	// (default 4000).
	PunchTimeoutMs int
	// PredictionSockets is the number of UDP source sockets used for the
	// symmetric-NAT block spray (n4-style). 0 disables the socket pool;
	// 1 = primary socket only. Values > 1 bind a contiguous local port block
	// and, against a hard (symmetric/unmeasurable) peer, aim every socket at
	// the peer's public port + PeerPortOffset, betting the NAT preserves the
	// local port. This needs no peer PortStep, so it reaches a cellular
	// CGNAT the step path cannot. Default (via Defaults): 25.
	PredictionSockets int
	// PeerPortOffset shifts the block spray off the peer's reported public
	// port (n4 "-o", default 20). Must be < PredictionSockets so the aim
	// lands inside the local block.
	PeerPortOffset int
	// SymmetricSpray is how many random ports the cone side fires per round at
	// a hard peer's public IP (paired with the hard side's plant leg -- the
	// birthday attack that connects a cellular CGNAT). 0 = SDK default (1024).
	SymmetricSpray int
	// SprayIPMax bounds how many distinct public addresses the cone side sprays
	// when a hard peer announces its CGNAT egress pool (a CIDR block inferred
	// from its sampled STUN addresses). 0 = SDK default (64).
	SprayIPMax int
	// PunchPPS caps probe packets sent per second per peer during punching. It
	// is a safety limit: an unthrottled wide CGNAT spray saturates the host NIC
	// and overflows the router's NAT conntrack table, taking the whole network
	// down. 0 = SDK default (1500).
	PunchPPS int
	// EscalateAfterMs is how long a peer classified as cone may fail to connect
	// before the engine re-plans it as hard (plant+spray). This recovers a
	// symmetric CGNAT that was flakily misdetected as cone, which otherwise
	// strands the link on a single public probe. 0 = engine default (3000).
	EscalateAfterMs int
	// STUNSecondaries is a comma-separated list of extra observation addresses
	// ("host:port,host:port") used to discover the destination-rotating CGNAT
	// candidate public IPs. Empty uses the built-in DefaultSecondaries. Set this
	// per deployment to STUN servers that are actually reachable from your
	// network/region -- the hole-punch generalization depends on the candidate
	// set covering the egress IP the peer direction uses, so region-appropriate
	// observation points matter.
	STUNSecondaries string
}

// Defaults returns a Config with the recommended values filled in.
func Defaults() *Config {
	return &Config{
		PortPrediction:    true,
		EnableLAN:         true,
		TimeoutSec:        15,
		ProbeIntervalMs:   200,
		PunchTimeoutMs:    4000,
		// 128 plant sockets: at 25 the cone peer only had ~25 mappings to collide
		// with against a 256-port blind window (~9.4%/round), which left a ~17s
		// tail on real cellular CGNATs. 128 raises per-round hit rate to ~40-53%,
		// pulling the tail into 2-4s. PunchPPS caps the rate so the larger pool
		// cannot flood the NIC/router.
		PredictionSockets: 128,
		PeerPortOffset:    20,
		SymmetricSpray:    1024,
		PunchPPS:          1500,
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
		c.ProbeIntervalMs = 200
	}
	if c.PunchTimeoutMs <= 0 {
		c.PunchTimeoutMs = 4000
	}
}
