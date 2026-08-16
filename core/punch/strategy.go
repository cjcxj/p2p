package punch

import (
	"net"

	"p2p/core/stun"
)

// Endpoint is one address the punch engine will probe.
type Endpoint struct {
	Addr  *net.UDPAddr
	Kind  string // "lan","public","predicted","relay"
	Order int
}

// NATInfo describes one side's reachability from the other side's
// perspective.
type NATInfo struct {
	Type        stun.NATType
	PublicAddr  *net.UDPAddr
	PrivateAddr *net.UDPAddr
	PortDelta   int
	RelayAddr   *net.UDPAddr
}

// Config tunes the punch engine.
type Config struct {
	// PortPrediction enables port-range probing for symmetric NATs.
	PortPrediction bool
	// RelayFallback enables the relay endpoint as a last resort.
	RelayFallback bool
	// EnableLAN allows probing the private address for same-LAN peers.
	EnableLAN bool
	// PredictionRange is the number of ports probed on each side of the
	// predicted symmetric mapping (default 4).
	PredictionRange int
	// ProbeInterval is the delay between probe bursts (default 200ms).
	ProbeIntervalMs int
	// PunchTimeout is how long to punch before trying the relay.
	PunchTimeoutMs int
	// OnLog, when set, receives verbose hole-punching flow messages.
	OnLog func(format string, args ...interface{})
}

// planTargets builds the ordered list of endpoints to probe for the remote
// peer, encoding the NAT combination strategy matrix. The same matrix is
// applied symmetrically by both sides (simultaneous probing).
func planTargets(my NATInfo, peer NATInfo, cfg Config) []Endpoint {
	var eps []Endpoint
	order := 0

	// LAN shortcut: same private network.
	if cfg.EnableLAN && peer.PrivateAddr != nil && my.PrivateAddr != nil &&
		peer.PrivateAddr.IP != nil && my.PrivateAddr.IP != nil {
		pe := peer.PrivateAddr.IP.To4()
		me := my.PrivateAddr.IP.To4()
		if pe != nil && me != nil && sameLAN(pe, me) {
			eps = append(eps, Endpoint{Addr: peer.PrivateAddr, Kind: "lan", Order: order})
			order++
		}
	}

	// Public address: always probed. Works for every cone combination and
	// often for symmetric (once the mapping exists, filtering may allow it).
	if peer.PublicAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.PublicAddr, Kind: "public", Order: order})
		order++
	}

	// Predicted symmetric mapping ports. A symmetric NAT increments the
	// mapped port by a constant delta per new destination mapping. The peer's
	// mapping for us is unknown, so we sweep a window around the port that
	// its mapping would use if it had already mapped us, plus a few mappings
	// ahead. Both sides sweep simultaneously, so one of the combined
	// (probe port, mapped port) pairs lines up.
	if cfg.PortPrediction && peer.PublicAddr != nil {
		span := cfg.PredictionRange
		if span <= 0 {
			span = 4
		}
		base := peer.PublicAddr.Port
		ports := make([]int, 0, span*4)
		if peer.PortDelta != 0 {
			// measured per-mapping delta: sweep around the predicted window
			for k := -span; k <= span*2; k++ {
				ports = append(ports, base+k*peer.PortDelta)
			}
		} else {
			// delta unknown (no STUN secondary): assume the common delta of
			// 1 and sweep a short forward window as a best effort
			for k := 1; k <= span; k++ {
				ports = append(ports, base+k)
			}
		}
		for _, port := range ports {
			if port < 1 || port > 65535 {
				continue
			}
			addr := &net.UDPAddr{IP: peer.PublicAddr.IP, Port: port}
			eps = append(eps, Endpoint{Addr: addr, Kind: "predicted", Order: order})
			order++
		}
	}

	// Relay: always reachable if the relay is up; keep as last resort.
	if cfg.RelayFallback && peer.RelayAddr != nil {
		eps = append(eps, Endpoint{Addr: peer.RelayAddr, Kind: "relay", Order: order})
		order++
	}
	return eps
}

func sameLAN(a, b net.IP) bool {
	return len(a) == 4 && len(b) == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
}
