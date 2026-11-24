package stun

import (
	"net"
	"sort"
	"time"
)

// DefaultStepSamples is how many fresh bindings MeasurePortStep opens to learn
// the allocator's increment. Four gives three deltas, enough to reject a
// non-monotonic allocator without spending a second of setup per sample.
const DefaultStepSamples = 4

// StepProbePort is the base local source port for spray and measurement
// sockets. n4 uses 30000; an allocator that advances with the local source
// port needs consecutive local ports to show it. A sample whose port is taken
// falls back to an ephemeral one, which still measures "advance per new binding".
const StepProbePort = 30000

// measureStep is Detect's opt-in hook: 0 unless the caller asked for samples.
func (c *Client) measureStep() int {
	if c.StepSamples <= 0 {
		return 0
	}
	return c.MeasurePortStep(nil, c.StepSamples)
}

// MeasurePortStep reports how much this NAT's public port moves for every new
// binding, measured against dst (default: the client's own server).
//
// This is the number that makes symmetric NAT punching tractable. A NAT can
// hand out a completely unpredictable port per destination -- so comparing two
// destinations tells you nothing -- while still advancing in small, ordered
// steps every time a new socket binds. 中国移动的 CGNAT 实测就是这一种:
// 同一 socket 换目的地是随机截距, 换 socket 则是每步约 +118 的单调前进.
//
// Returns 0 when the allocator is not steady enough to predict: a reported
// step is only useful if binding k more sockets really walks the port about
// step*k away, and that fails whenever the steps disagree in direction or
// vary by more than they agree.
func (c *Client) MeasurePortStep(dst *net.UDPAddr, samples int) int {
	if dst == nil {
		if c.Server == nil {
			return 0
		}
		dst = c.Server
	}
	if samples <= 0 {
		samples = DefaultStepSamples
	}
	timeout := c.SecondaryTimeout
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	return c.measureStepFrom(StepProbePort, dst, samples, timeout)
}

func (c *Client) measureStepFrom(base int, dst *net.UDPAddr, samples int, timeout time.Duration) int {
	ports := make([]int, 0, samples)
	for i := 0; i < samples; i++ {
		p, err := probeFrom(base+i, dst, timeout)
		if err != nil {
			continue
		}
		ports = append(ports, p)
	}
	if len(ports) < 3 {
		return 0
	}

	deltas := make([]int, 0, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		deltas = append(deltas, ports[i]-ports[i-1])
	}
	sorted := append([]int(nil), deltas...)
	sort.Ints(sorted)
	med := sorted[len(sorted)/2]
	if med == 0 {
		return 0
	}
	// Most steps must go the same way and stay within a factor of four of the
	// median, otherwise a forward window of k*step would not contain the peer's
	// mapping often enough to be worth the extra packets.
	same := 0
	for _, d := range deltas {
		if (d > 0) == (med > 0) && abs(d) >= abs(med)/4 && abs(d) <= abs(med)*4 {
			same++
		}
	}
	if same*3 < len(deltas)*2 {
		return 0
	}
	if a := abs(med); a > 4096 {
		return 0
	}
	return med
}

// probeFrom asks dst what it sees, from one specific local source port.
func probeFrom(localPort int, dst *net.UDPAddr, timeout time.Duration) (int, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: localPort})
	if err != nil {
		// The port is in use on this host; the measurement does not need it,
		// it only needs a new binding to exist.
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			return 0, err
		}
	}
	defer conn.Close()
	c := &Client{Conn: conn, Server: dst, Retries: 0, Timeout: timeout}
	msg, _, err := c.BindRequest(false, false)
	if err != nil {
		return 0, err
	}
	mapped, err := msg.MappedAddress()
	if err != nil {
		return 0, err
	}
	return mapped.Port, nil
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
