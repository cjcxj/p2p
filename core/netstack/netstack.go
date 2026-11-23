// Package netstack provides a userspace IPv4 endpoint backed by gVisor's
// netstack. Packets addressed to a local virtual IP are injected here and
// handled entirely in-process (ICMP echo replies, TCP/UDP endpoints via the
// stack) instead of relying on the host kernel, which on Android does not
// reliably route replies back through a VpnService tun interface.
package netstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const mtu = 1280

// tcpForwarderMaxInFlight bounds simultaneous userspace TCP handshakes.
const tcpForwarderMaxInFlight = 1024

// LocalStack owns one virtual address in a userspace IP stack.
type LocalStack struct {
	s     *stack.Stack
	ep    *channel.Endpoint
	vip   tcpip.Address
	net   *net.IPNet
	mu    sync.Mutex
	send  func(ipPkt []byte)
	close chan struct{}
	once  sync.Once
}

// NewLocalStack creates a userspace stack holding vip in subnet. Outbound
// packets emitted by the stack (e.g. ICMP echo replies) are delivered to
// send.
func NewLocalStack(vip net.IP, subnet *net.IPNet, send func(ipPkt []byte)) (*LocalStack, error) {
	if v4 := vip.To4(); v4 == nil {
		return nil, fmt.Errorf("netstack: ipv4 only")
	}
	if send == nil {
		send = func([]byte) {}
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	ep := channel.New(1024, mtu, tcpip.LinkAddress([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}))
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, fmt.Errorf("netstack: create nic: %s", err)
	}
	addr := tcpip.AddrFromSlice(vip.To4())
	ones, _ := subnet.Mask.Size()
	awp := tcpip.AddressWithPrefix{Address: addr, PrefixLen: ones}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: awp,
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netstack: add address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: awp.Subnet(),
			NIC:         1,
		},
	})
	ls := &LocalStack{
		s:     s,
		ep:    ep,
		vip:   addr,
		net:   subnet,
		send:  send,
		close: make(chan struct{}),
	}

	// Forward unhandled inbound TCP to 127.0.0.1:<same port>. This makes
	// services that listen on 0.0.0.0 reachable through the virtual IP even
	// when the host firewall drops new connections on the TUN interface.
	tcpFwd := tcp.NewForwarder(s, 0, tcpForwarderMaxInFlight, func(req *tcp.ForwarderRequest) {
		go ls.handleTCPForwarder(req)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	go ls.drain()
	return ls, nil
}

// handleTCPForwarder accepts an inbound TCP connection in the userspace stack
// and proxies it to a local service listening on 127.0.0.1:same-port.
func (l *LocalStack) handleTCPForwarder(req *tcp.ForwarderRequest) {
	port := req.ID().LocalPort
	if port == 0 {
		req.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)

	client := gonet.NewTCPConn(&wq, ep)
	upstream, derr := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if derr != nil {
		client.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		_ = client.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

// HandleInbound feeds a raw IPv4 packet into the userspace stack. Only
// packets destined to the local virtual address are expected.
func (l *LocalStack) HandleInbound(ipPkt []byte) {
	if len(ipPkt) < 20 || ipPkt[0]>>4 != 4 {
		return
	}
	// static neighbor so replies to the sender do not require ARP
	src := tcpip.AddrFromSlice(ipPkt[12:16])
	_ = l.s.AddStaticNeighbor(1, ipv4.ProtocolNumber, src,
		tcpip.LinkAddress([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipPkt),
	})
	defer pkt.DecRef()
	l.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
}

// drain reads packets emitted by the stack and routes them out.
func (l *LocalStack) drain() {
	for {
		pkt := l.ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		out := append([]byte(nil), view.AsSlice()...)
		pkt.DecRef()
		if len(out) >= 20 {
			l.mu.Lock()
			fn := l.send
			l.mu.Unlock()
			fn(out)
		}
	}
}

// Close stops the stack.
func (l *LocalStack) Close() {
	l.once.Do(func() {
		close(l.close)
		l.s.Close()
		l.ep.Close()
	})
}

// Wants reports whether the userspace stack should handle a raw IPv4 packet
// addressed to the local virtual address. Currently it handles ICMP echo
// requests (answered in-process) and TCP (accepted in-process and forwarded
// to the local host). UDP and other traffic are left to the host kernel.
func (l *LocalStack) Wants(pkt []byte) bool {
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+4 > len(pkt) {
		return false
	}
	if !tcpip.AddrFromSlice(pkt[16:20]).Equal(l.vip) {
		return false
	}
	switch pkt[9] {
	case 1: // ICMP
		return pkt[ihl] == 8 // echo request
	case 6: // TCP
		return true
	}
	return false
}

// ExposeTCP makes the virtual address accept TCP connections on port and
// forwards them to 127.0.0.1:port on the host. This lets other nodes reach
// TCP services running locally on this device through the virtual IP.
func (l *LocalStack) ExposeTCP(port uint16) error {
	ln, err := gonet.ListenTCP(l.s, tcpip.FullAddress{NIC: 1, Addr: l.vip, Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		return fmt.Errorf("netstack: listen tcp %d: %s", port, err)
	}
	go l.acceptLoop(ln, port)
	return nil
}

func (l *LocalStack) acceptLoop(ln *gonet.TCPListener, port uint16) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go l.pipeToLocal(conn, port)
	}
}

func (l *LocalStack) pipeToLocal(client net.Conn, port uint16) {
	defer client.Close()
	up, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, client); done <- struct{}{} }()
	go func() { io.Copy(client, up); done <- struct{}{} }()
	<-done
}
