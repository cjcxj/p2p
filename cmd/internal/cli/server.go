// RunServer runs the all-in-one P2P server on a single port: signaling
// (TCP) plus STUN and relay (UDP) share the same port number, with an
// optional best-effort STUN secondary socket on port+1 for richer NAT
// detection.
package cli

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"p2p/core/signaling"
	"p2p/core/stun"
)

func RunServer(args []string) int {
	fs := flag.NewFlagSet("p2p server", flag.ExitOnError)
	port := fs.Int("port", 8080, "single service port (TCP signaling + UDP STUN/relay)")
	verbose := fs.Bool("verbose", false, "log room membership and signaling events")
	stunIP2 := fs.String("stun-ip2", "", "optional secondary IP for full-cone detection")
	stunSecondary := fs.Bool("stun-secondary", false, "also bind STUN on port+1 for richer NAT detection (firewall must open it)")
	network := fs.String("network", "10.9.0.0/24", "virtual subnet for per-room address allocation (0.0.0.0/0 disables)")
	secret := fs.String("secret", "", "shared pre-shared key for mutual client/server authentication")
	users := fs.String("users", "", "per-user credentials 'user:pass,user2:pass2' (enables per-user auth)")
	maxConnsPerIP := fs.Int("max-conns-per-ip", 0, "max concurrent signaling connections per source IP (0 = unlimited)")
	maxRoomMembers := fs.Int("max-room-members", 0, "max members per room (0 = unlimited)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (PEM); enables TLS signaling")
	tlsKey := fs.String("tls-key", "", "TLS private key file (PEM); requires --tls-cert")
	fs.Parse(args)

	logger := log.New(os.Stdout, "[p2p-server] ", log.LstdFlags)

	var tlsCfg *tls.Config
	if *tlsCert != "" || *tlsKey != "" {
		if *tlsCert == "" || *tlsKey == "" {
			logger.Fatalf("--tls-cert and --tls-key must be provided together")
		}
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			logger.Fatalf("tls: %v", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
		logger.Printf("signaling TLS enabled")
	}

	// ---- Shared UDP socket: STUN + relay ----
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		logger.Fatalf("udp: %v", err)
	}
	defer udpConn.Close()

	logger.Printf("STUN UDP on :%d (ensure UDP %d is open on the firewall)", *port, *port)

	// Optional best-effort secondary STUN socket on port+1 (enables the
	// change-port test and symmetric detection when reachable; not required
	// for basic operation). Off by default so the service binds a single
	// port.
	var secondary *net.UDPConn
	if *stunSecondary {
		if sec, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port + 1}); err == nil {
			secondary = sec
			defer sec.Close()
			go stunReadLoop(sec)
			logger.Printf("STUN secondary UDP on :%d (optional)", *port+1)
		} else {
			logger.Printf("STUN secondary UDP on :%d unavailable (%v); NAT classification degraded", *port+1, err)
		}
	}

	var ip2Conn *net.UDPConn
	if *stunIP2 != "" {
		if c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(*stunIP2), Port: *port}); err == nil {
			ip2Conn = c
			defer c.Close()
			go stunReadLoop(c)
			logger.Printf("STUN secondary IP %s:%d", *stunIP2, *port)
		}
	}

	// ---- Signaling (TCP) ----
	sigSrv, err := signaling.NewServer(fmt.Sprintf("0.0.0.0:%d", *port), signaling.Options{
		Network:        *network,
		Secret:         *secret,
		Users:          parseUsers(*users),
		MaxConnsPerIP:  *maxConnsPerIP,
		MaxRoomMembers: *maxRoomMembers,
		TLSConfig:      tlsCfg,
		Logger:         logger,
		Verbose:        *verbose,
	})
	if err != nil {
		logger.Fatalf("signaling: %v", err)
	}
	defer sigSrv.Close()
	logger.Printf("signaling TCP on :%d", *port)
	logger.Printf("virtual network: %s", sigSrv.Network())

	// ---- Shared socket STUN loop ----
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			if stun.IsSTUN(data) {
				if msg, err := stun.Decode(data); err == nil && msg.Type == stun.BindingRequest {
					stun.AnswerBinding(udpConn, secondary, ip2Conn, msg, src)
				}
			}
			// else: drop unknown traffic (pure P2P: no relay to forward to)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logger.Printf("shutting down")
	return 0
}

// parseUsers parses "user:pass,user2:pass2" into a map.
func parseUsers(spec string) map[string]string {
	if spec == "" {
		return nil
	}
	out := make(map[string]string)
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// stunReadLoop serves STUN binding requests on a dedicated socket (secondary
// port or secondary IP).
func stunReadLoop(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < stun.HeaderLength {
			continue
		}
		msg, err := stun.Decode(buf[:n])
		if err != nil || msg.Type != stun.BindingRequest {
			continue
		}
		stun.AnswerBinding(conn, nil, nil, msg, src)
	}
}
