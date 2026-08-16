// Command stress runs a local loopback data-plane stress test between two
// in-process p2p sessions. It is a development tool for throughput/regression
// checks, not a substitute for real multi-NAT production testing.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"p2p/core/signaling"
	"p2p/core/stun"
	p2p "p2p/sdk"
)

type stressListener struct {
	connected chan string
	data      chan []byte
	once      sync.Once
}

func newStressListener() *stressListener {
	return &stressListener{
		connected: make(chan string, 1),
		data:      make(chan []byte, 4096),
	}
}

func (l *stressListener) OnEvent(event int, peerID string, data []byte) {
	switch event {
	case p2p.EventPeerConnected:
		l.once.Do(func() { l.connected <- peerID })
	case p2p.EventData:
		l.data <- append([]byte(nil), data...)
	}
}

func main() {
	var (
		count   = flag.Int("count", 10000, "number of messages to send")
		size    = flag.Int("size", 512, "payload size in bytes")
		room    = flag.String("room", "stress", "room id")
		timeout = flag.Int("timeout", 10, "connect timeout in seconds")
	)
	flag.Parse()
	if *count <= 0 || *size <= 0 {
		fmt.Fprintln(os.Stderr, "error: --count and --size must be positive")
		os.Exit(2)
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		log.Fatalf("udp: %v", err)
	}
	defer udpConn.Close()
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := signaling.NewServer(addr, signaling.Options{})
	if err != nil {
		log.Fatalf("signaling server: %v", err)
	}
	defer srv.Close()
	go stunReadLoop(udpConn)
	log.Printf("signaling+STUN on %s", addr)

	la := newStressListener()
	lb := newStressListener()

	cfg := func(l *stressListener) *p2p.Config {
		c := p2p.Defaults()
		c.ServerAddr = addr
		c.STUNAddr = addr
		c.Token = ""
		c.TimeoutSec = *timeout
		c.Debug = false
		return c
	}

	sa, err := p2p.NewSession(cfg(la), la)
	if err != nil {
		log.Fatalf("session A: %v", err)
	}
	defer sa.Disconnect()
	sb, err := p2p.NewSession(cfg(lb), lb)
	if err != nil {
		log.Fatalf("session B: %v", err)
	}
	defer sb.Disconnect()

	if err := sa.Connect(*room); err != nil {
		log.Fatalf("connect A: %v", err)
	}
	if err := sb.Connect(*room); err != nil {
		log.Fatalf("connect B: %v", err)
	}

	// Wait until both sides see a connected peer.
	select {
	case <-la.connected:
	case <-time.After(time.Duration(*timeout+5) * time.Second):
		log.Fatal("timed out waiting for A to connect")
	}
	select {
	case <-lb.connected:
	case <-time.After(time.Duration(*timeout+5) * time.Second):
		log.Fatal("timed out waiting for B to connect")
	}

	dst := sb.LocalIP()
	if dst == "" {
		log.Fatal("B has no virtual IP")
	}
	log.Printf("A -> B (%s), count=%d size=%d", dst, *count, *size)

	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		for received < *count {
			<-lb.data
			received++
		}
	}()

	start := time.Now()
	for i := 0; i < *count; i++ {
		if err := sa.SendToIP(dst, payload); err != nil {
			log.Fatalf("send %d: %v", i, err)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	secs := elapsed.Seconds()
	msgRate := float64(*count) / secs
	byteRate := float64(*count) * float64(*size) / secs
	fmt.Printf("elapsed: %s\n", elapsed)
	fmt.Printf("messages/sec: %.0f\n", msgRate)
	fmt.Printf("bytes/sec: %.0f\n", byteRate)
}

func stunReadLoop(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < stun.HeaderLength || !stun.IsSTUN(buf[:n]) {
			continue
		}
		msg, err := stun.Decode(buf[:n])
		if err != nil || msg.Type != stun.BindingRequest {
			continue
		}
		stun.AnswerBinding(conn, nil, nil, msg, src)
	}
}
