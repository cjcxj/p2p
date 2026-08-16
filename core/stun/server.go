package stun

import (
	"encoding/binary"
	"net"
	"sync"
)

// Server is a minimal STUN server. It listens on basePort and basePort+1 so
// that CHANGE-REQUEST{change port} tests can be answered. If ip2 is non-nil
// it also binds the same ports on the secondary IP so that
// CHANGE-REQUEST{change IP} tests work; otherwise change-IP requests are
// dropped (never answered), which is the conservative behaviour for a
// single-IP deployment.
type Server struct {
	ln   []listener
	ip2  net.IP
	wg   sync.WaitGroup
	done chan struct{}
	once sync.Once
}

type listener struct {
	conn    *net.UDPConn
	port    int
	onIP2   bool
}

// NewServer starts a STUN server on ip:basePort (and basePort+1), plus the
// same two ports on ip2 when provided. Returns a running server.
func NewServer(ip string, basePort int, ip2 string) (*Server, error) {
	s := &Server{done: make(chan struct{})}
	if ip2 != "" {
		s.ip2 = net.ParseIP(ip2)
	}
	primary := net.ParseIP(ip)
	if primary == nil {
		primary = net.IPv4zero
	}
	ports := []int{basePort, basePort + 1}
	for _, port := range ports {
		addr := &net.UDPAddr{IP: primary, Port: port}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.ln = append(s.ln, listener{conn: conn, port: port})
	}
	if s.ip2 != nil {
		for _, port := range ports {
			addr := &net.UDPAddr{IP: s.ip2, Port: port}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				s.Close()
				return nil, err
			}
			s.ln = append(s.ln, listener{conn: conn, port: port, onIP2: true})
		}
	}
	for _, l := range s.ln {
		s.wg.Add(1)
		go s.readLoop(l.conn)
	}
	return s, nil
}

// Addrs returns the primary bind addresses (base and base+1).
func (s *Server) Addrs() []*net.UDPAddr {
	var out []*net.UDPAddr
	for _, l := range s.ln {
		if l.onIP2 {
			continue
		}
		out = append(out, l.conn.LocalAddr().(*net.UDPAddr))
		if len(out) == 2 {
			break
		}
	}
	return out
}

func (s *Server) readLoop(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < HeaderLength {
			continue
		}
		msg, err := Decode(buf[:n])
		if err != nil || msg.Type != BindingRequest {
			continue
		}
		s.handle(conn, msg, src)
	}
}

// IsSTUN reports whether a datagram looks like a STUN message (by magic
// cookie). Used by multiplexed servers to demultiplex STUN from other
// protocols on a shared UDP socket.
func IsSTUN(b []byte) bool {
	return len(b) >= 8 && binary.BigEndian.Uint32(b[4:8]) == MagicCookie
}

// AnswerBinding answers a binding request received on recv. It honours
// CHANGE-REQUEST using the optional secondary (different port) and ip2
// (different IP) responder sockets; when a requested change cannot be
// honoured it stays silent so clients classify conservatively. This lets a
// shared UDP socket multiplex STUN with other traffic.
func AnswerBinding(recv, secondary, ip2 *net.UDPConn, req *Message, src *net.UDPAddr) {
	changeIP, changePort, _ := req.ChangeRequest()
	resp := NewBindingSuccess(req.TID)
	resp.SetXORMappedAddress(src.IP, src.Port)
	resp.AddSoftware("p2p")
	var responder *net.UDPConn
	switch {
	case changeIP && ip2 != nil:
		responder = ip2
	case changePort && secondary != nil:
		responder = secondary
	case changeIP, changePort:
		// a requested change cannot be honoured (single port / single IP):
		// stay silent so clients classify conservatively instead of getting a
		// false "not port-restricted" result
		responder = nil
	default:
		responder = recv
	}
	if responder == nil {
		return
	}
	responder.WriteToUDP(resp.Encode(), src)
}

// handle answers a binding request from the appropriate responder socket.
func (s *Server) handle(recv *net.UDPConn, req *Message, src *net.UDPAddr) {
	recvPort := recv.LocalAddr().(*net.UDPAddr).Port
	recvOnIP2 := false
	for _, l := range s.ln {
		if l.conn == recv {
			recvOnIP2 = l.onIP2
			break
		}
	}
	var secondary, ip2 *net.UDPConn
	for _, l := range s.ln {
		switch {
		case l.onIP2 == recvOnIP2 && l.port != recvPort:
			secondary = l.conn
		case l.onIP2 && !recvOnIP2 && l.port == recvPort:
			ip2 = l.conn
		}
	}
	AnswerBinding(recv, secondary, ip2, req, src)
}

// Close stops the server.
func (s *Server) Close() {
	s.once.Do(func() {
		close(s.done)
		for _, l := range s.ln {
			l.conn.Close()
		}
		s.wg.Wait()
	})
}
