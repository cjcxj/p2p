// Command tput measures raw TCP throughput over the hole-punched WireGuard
// tunnel (or any IP path) between two p2p nodes. It is a development tool: run
// one side as -mode server (listens, counts received bytes, prints the rate on
// disconnect) and the other as -mode client -addr <ip:port> (saturates the
// socket for -seconds and prints its send rate). Swap the roles to measure the
// opposite direction. This exists because a phone has no iperf3 binary while the
// desktop does, so a matched in-repo tool gives a real cross-tunnel number.
//
// -proto udp adds a loss measurement that TCP hides behind retransmission: the
// client stamps every datagram with a sequence number and the server counts
// gaps. Streaming quality is exactly this, which is why a TCP number that looks
// great can still drop on live video.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	addr := flag.String("addr", "0.0.0.0:5201", "listen (server) or dial (client) address")
	seconds := flag.Int("seconds", 10, "how long the client pushes / server measures")
	proto := flag.String("proto", "tcp", "tcp or udp")
	dir := flag.String("dir", "send", "tcp client: send (uplink) or recv (downlink)")
	targetMbps := flag.Int("mbps", 20, "udp: target send rate in Mbps")
	pkt := flag.Int("pkt", 1200, "udp: payload bytes per datagram")
	flag.Parse()

	switch *mode {
	case "server":
		if *proto == "udp" {
			runUDPServer(*addr, *seconds, *pkt)
		} else {
			runServer(*addr)
		}
	case "client":
		if *proto == "udp" {
			runUDPClient(*addr, *targetMbps, *pkt, time.Duration(*seconds)*time.Second)
		} else {
			runClient(*addr, *dir, time.Duration(*seconds)*time.Second)
		}
	default:
		fmt.Fprintln(os.Stderr, "mode must be server or client")
		os.Exit(2)
	}
}

func mbps(bytes int64, d time.Duration) string {
	if d <= 0 {
		d = time.Millisecond
	}
	secs := d.Seconds()
	mb := float64(bytes) * 8 / 1e6 / secs
	return fmt.Sprintf("%.1f Mbps (%.1f MB/s)", mb, float64(bytes)/1e6/secs)
}

func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("tput server listening on %s\n", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go serve(c)
	}
}

func serve(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	start := time.Now()
	payload := make([]byte, 128*1024)
	if hdr[0] == 'r' {
		secs := int(hdr[1])
		if secs <= 0 {
			secs = 10
		}
		deadline := start.Add(time.Duration(secs) * time.Second)
		var sent int64
		for time.Now().Before(deadline) {
			n, err := c.Write(payload)
			sent += int64(n)
			if err != nil {
				break
			}
		}
		elapsed := time.Since(start)
		fmt.Printf("pushed %d bytes in %s -> %s\n", sent, elapsed.Round(time.Millisecond), mbps(sent, elapsed))
		return
	}
	var total int64
	buf := make([]byte, 256*1024)
	for {
		n, err := c.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	fmt.Printf("recv %d bytes in %s -> %s\n", total, time.Since(start).Round(time.Millisecond), mbps(total, time.Since(start)))
}

func runClient(addr, dir string, dur time.Duration) {
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	secs := int(dur.Seconds())
	if secs > 255 {
		secs = 255
	}
	start := time.Now()
	var total int64
	payload := make([]byte, 128*1024)

	if dir == "recv" {
		if _, err := conn.Write([]byte{'r', byte(secs)}); err != nil {
			fmt.Fprintln(os.Stderr, "hdr:", err)
			return
		}
		_ = conn.SetReadDeadline(start.Add(dur + 5*time.Second))
		buf := make([]byte, 256*1024)
		for {
			n, err := conn.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
	} else {
		if _, err := conn.Write([]byte{'s', byte(secs)}); err != nil {
			fmt.Fprintln(os.Stderr, "hdr:", err)
			return
		}
		deadline := start.Add(dur)
		for time.Now().Before(deadline) {
			n, err := conn.Write(payload)
			total += int64(n)
			if err != nil {
				fmt.Fprintln(os.Stderr, "write:", err)
				break
			}
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("client %s %d bytes in %s -> %s\n", dir, total, elapsed.Round(time.Millisecond), mbps(total, elapsed))
}

// runUDPClient sends seq-stamped datagrams at a fixed target bitrate.
func runUDPClient(addr string, targetMbps, pktSize int, dur time.Duration) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	buf := make([]byte, 8+pktSize)
	// Windows time.Now()/ticker granularity is ~610us, so a per-packet ticker
	// cannot pace above ~15 Mbps. Send bursts every 10ms instead: the burst size
	// encodes the target rate and the coarse tick is honored.
	chunk := 10 * time.Millisecond
	pktsPerChunk := int(float64(targetMbps) * 1e6 / 8 * chunk.Seconds() / float64(8+pktSize))
	if pktsPerChunk < 1 {
		pktsPerChunk = 1
	}
	ticker := time.NewTicker(chunk)
	defer ticker.Stop()

	var seq uint64
	start := time.Now()
	deadline := start.Add(dur)
	for time.Now().Before(deadline) {
		<-ticker.C
		for j := 0; j < pktsPerChunk; j++ {
			binary.BigEndian.PutUint64(buf[:8], seq)
			if _, err := conn.Write(buf); err != nil {
				fmt.Fprintln(os.Stderr, "write:", err)
				break
			}
			seq++
		}
	}
	fmt.Printf("udp sent %d datagrams size=%d target=%d Mbps over %s\n",
		seq, pktSize, targetMbps, time.Since(start).Round(time.Millisecond))
}

// runUDPServer counts received datagrams and detects gaps via seq numbers until
// the -seconds deadline.
func runUDPServer(addr string, seconds, pktSize int) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer pc.Close()
	fmt.Printf("tput udp server on %s measuring %ds\n", pc.LocalAddr(), seconds)

	// Big socket read buffer to reduce kernel-side drops (which would look like
	// path loss but are actually receive-window loss at this end).
	_ = pc.SetReadBuffer(8 << 20)

	buf := make([]byte, 65536)
	start := time.Now()
	deadline := start.Add(time.Duration(seconds) * time.Second)
	var got, lost int
	var haveLast bool
	var lastSeq uint64
	for {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		_ = pc.SetReadDeadline(time.Now().Add(left))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if n < 8 {
			continue
		}
		seq := binary.BigEndian.Uint64(buf[:8])
		if !haveLast {
			haveLast = true
		} else if seq > lastSeq+1 {
			lost += int(seq - lastSeq - 1)
		}
		if !haveLast || seq > lastSeq {
			lastSeq = seq
		}
		got++
	}
	elapsed := time.Since(start)
	exp := got + lost
	lossPct := 0.0
	if exp > 0 {
		lossPct = 100 * float64(lost) / float64(exp)
	}
	fmt.Printf("udp recv %d expected %d lost %d (%.2f%%) in %s -> %s\n",
		got, exp, lost, lossPct, elapsed.Round(time.Millisecond), mbps(int64(got)*int64(pktSize), elapsed))
}
