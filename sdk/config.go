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

	// RelayEnabled enables the relay fallback when hole punching fails.
	RelayEnabled bool
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

	// TimeoutSec bounds the whole connection attempt (default 15).
	TimeoutSec int
	// ProbeIntervalMs is the delay between probe bursts (default 200).
	ProbeIntervalMs int
	// PunchTimeoutMs is how long to punch before falling back to relay
	// (default 4000).
	PunchTimeoutMs int
}

// Defaults returns a Config with the recommended values filled in.
func Defaults() *Config {
	return &Config{
		RelayEnabled:    true,
		PortPrediction:  true,
		EnableLAN:       true,
		TimeoutSec:      15,
		ProbeIntervalMs: 200,
		PunchTimeoutMs:  4000,
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
