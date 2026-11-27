package stun

import (
	"net"
	"sort"
	"sync"
	"time"
)

// DefaultStepSamples is how many fresh bindings MeasurePortStep opens concurrently
// in 1 RTT to learn the allocator's behaviour (port step, port-preservation, and PBA port block).
const DefaultStepSamples = 8

// StepProbePort is the base local source port for spray and measurement
// sockets. An allocator that advances with the local source port needs
// consecutive local ports to show it.
const StepProbePort = 30000

// PortPattern summarises the NAT's port allocation behaviour across consecutive
// local bindings toward a destination.
type PortPattern struct {
	PortStep           int
	PortPreserve       bool
	PortPreserveOffset int
	BlockMin           int
	BlockMax           int
	SamplePorts        []int
}

// measurePattern is Detect's opt-in hook: empty unless StepSamples > 0.
func (c *Client) measurePattern() PortPattern {
	if c.StepSamples <= 0 {
		return PortPattern{}
	}
	timeout := c.SecondaryTimeout
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	return AnalyzeAllocation(c.Server, StepProbePort, c.StepSamples, timeout)
}

// MeasurePortStep reports how much this NAT's public port moves for every new
// binding, measured against dst (default: the client's own server).
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
		timeout = 700 * time.Millisecond
	}
	return AnalyzeAllocation(dst, StepProbePort, samples, timeout).PortStep
}

// AnalyzeAllocation probes dst concurrently from `samples` consecutive sockets
// starting at local port `base` (falling back to ephemeral ports if busy) and
// classifies whether the NAT is:
//   - Port-preserving (mapped_port - local_port == constant offset),
//   - Linearly stepping (mapped_port[i] - mapped_port[i-1] ≈ constant PortStep),
//   - Port Block Allocation / PBA (all mapped ports cluster inside <= 2048 ports).
func AnalyzeAllocation(dst *net.UDPAddr, base int, samples int, timeout time.Duration) PortPattern {
	if dst == nil || samples < 3 {
		return PortPattern{}
	}
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}

	type sampleRes struct {
		idx       int
		localPort int
		mapped    int
		ok        bool
	}

	results := make([]sampleRes, samples)
	var wg sync.WaitGroup
	for i := 0; i < samples; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			lp, mp, err := probeFrom(base+idx, dst, timeout)
			if err != nil {
				return
			}
			results[idx] = sampleRes{
				idx:       idx,
				localPort: lp,
				mapped:    mp,
				ok:        true,
			}
		}(i)
	}
	wg.Wait()

	var valid []sampleRes
	for _, r := range results {
		if r.ok {
			valid = append(valid, r)
		}
	}
	if len(valid) < 3 {
		return PortPattern{}
	}

	ports := make([]int, len(valid))
	offsets := make([]int, len(valid))
	minP, maxP := valid[0].mapped, valid[0].mapped
	for i, r := range valid {
		ports[i] = r.mapped
		offsets[i] = r.mapped - r.localPort
		if r.mapped < minP {
			minP = r.mapped
		}
		if r.mapped > maxP {
			maxP = r.mapped
		}
	}

	pat := PortPattern{
		SamplePorts: ports,
	}
	if maxP-minP <= 2048 {
		pat.BlockMin = minP
		pat.BlockMax = maxP
	}

	// Check port-preserving behaviour: mapped_port - local_port ≈ constant.
	sortedOff := append([]int(nil), offsets...)
	sort.Ints(sortedOff)
	medOff := sortedOff[len(sortedOff)/2]
	preserveHits := 0
	for _, off := range offsets {
		if abs(off-medOff) <= 2 {
			preserveHits++
		}
	}
	if preserveHits*3 >= len(offsets)*2 {
		pat.PortPreserve = true
		pat.PortPreserveOffset = medOff
	}

	// Check steady per-binding step across consecutive sample indices.
	var deltas []int
	for i := 1; i < len(valid); i++ {
		idxDiff := valid[i].idx - valid[i-1].idx
		if idxDiff <= 0 {
			continue
		}
		deltas = append(deltas, (valid[i].mapped-valid[i-1].mapped)/idxDiff)
	}
	if len(deltas) >= 2 {
		sorted := append([]int(nil), deltas...)
		sort.Ints(sorted)
		med := sorted[len(sorted)/2]
		if med != 0 && abs(med) <= 4096 {
			same := 0
			for _, d := range deltas {
				if (d > 0) == (med > 0) && abs(d) >= abs(med)/4 && abs(d) <= abs(med)*4 {
					same++
				}
			}
			if same*3 >= len(deltas)*2 {
				pat.PortStep = med
			}
		}
	}
	return pat
}

// probeFrom asks dst what it sees from one specific local source port, returning
// (actualLocalPort, mappedPublicPort, error).
func probeFrom(localPort int, dst *net.UDPAddr, timeout time.Duration) (int, int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
		if err != nil {
			return 0, 0, err
		}
	}
	defer conn.Close()
	actualLocal := conn.LocalAddr().(*net.UDPAddr).Port
	c := &Client{Conn: conn, Server: dst, Retries: 0, Timeout: timeout}
	msg, _, err := c.BindRequest(false, false)
	if err != nil {
		return 0, 0, err
	}
	mapped, err := msg.MappedAddress()
	if err != nil {
		return 0, 0, err
	}
	return actualLocal, mapped.Port, nil
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
