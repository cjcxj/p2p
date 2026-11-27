package wgengine

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// The tunnel must be able to send through a caller-supplied router instead of
// its fixed socket, so the WireGuard data plane can follow the punch engine's
// winning socket per peer.
func TestBindSendUsesSender(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	var got []byte
	var addr *net.UDPAddr
	b.SetSender(func(buf []byte, dst *net.UDPAddr) error {
		got = append([]byte(nil), buf...)
		addr = dst
		return nil
	})

	ep, err := b.ParseEndpoint("203.0.113.7:44000")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	if err := b.Send([][]byte{{9, 8, 7}}, ep); err != nil {
		t.Fatalf("send: %v", err)
	}
	if addr == nil || addr.String() != "203.0.113.7:44000" {
		t.Fatalf("router not used, dst=%v", addr)
	}
	if len(got) != 3 || got[0] != 9 {
		t.Fatalf("router payload wrong: %v", got)
	}
}

// Without a router the bind still writes through its own socket.
func TestBindSendFallsBackToConn(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	b := NewBind(pc)
	b.SetSender(nil) // no router: Send must use pc
	self := pc.LocalAddr().(*net.UDPAddr)
	ep, err := b.ParseEndpoint(self.String())
	if err != nil {
		t.Fatalf("parse self: %v", err)
	}
	if err := b.Send([][]byte{{1, 2, 3, 4}}, ep); err != nil {
		t.Fatalf("send through conn: %v", err)
	}
}

func fakeInit() []byte {
	pkt := make([]byte, initSize)
	pkt[0] = 1 // Handshake Initiation
	return pkt
}

func listenBind(t *testing.T) *Bind {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return NewBind(pc)
}

// The whole point of the cache: an initiation that arrived while no peer was
// configured must still be answered once one is.
func TestInitiationReplayedAfterPeer(t *testing.T) {
	b := listenBind(t)
	from := &net.UDPAddr{IP: net.ParseIP("203.0.113.9").To4(), Port: 45000}
	b.Ingest(fakeInit(), from)

	// Ingest forwards to the device as well as caching, because the device may
	// already know the peer. Drain that copy so what follows measures the replay.
	select {
	case <-b.rx:
	default:
		t.Fatal("the initiation was not offered to the device at all")
	}

	b.ReplayInitiation("203.0.113.9:45000")
	select {
	case in := <-b.rx:
		if in.from.String() != "203.0.113.9:45000" || in.n != initSize || in.buf[0] != 1 {
			t.Fatalf("replayed wrong packet: from=%v n=%d type=%d", in.from, in.n, in.buf[0])
		}
	default:
		t.Fatal("nothing replayed for a peer that was configured after the initiation")
	}

	// One initiation, one answer: a second replay would be a replay of a
	// consumed handshake.
	b.ReplayInitiation("203.0.113.9:45000")
	select {
	case <-b.rx:
		t.Fatal("the same initiation was replayed twice")
	default:
	}
}

func TestInitiationCacheExpiryAndForget(t *testing.T) {
	b := listenBind(t)
	from := &net.UDPAddr{IP: net.ParseIP("203.0.113.10").To4(), Port: 46000}
	b.Ingest(fakeInit(), from)
	<-b.rx // drain the copy that went to the device
	// Aged beyond the TTL it must be dropped rather than answered late.
	ap, _ := netip.ParseAddrPort("203.0.113.10:46000")
	b.recentInit[ap] = cachedInit{pkt: fakeInit(), at: time.Now().Add(-2 * initCacheTTL)}
	b.ReplayInitiation("203.0.113.10:46000")
	select {
	case <-b.rx:
		t.Fatal("an expired initiation was replayed")
	default:
	}
	if len(b.recentInit) != 0 {
		t.Fatalf("expired entry left in the cache: %d", len(b.recentInit))
	}

	// Explicit forget: a peer removed and re-added under a new key must not be
	// answered with the previous session's initiation.
	b.Ingest(fakeInit(), from)
	<-b.rx // drain the copy that went to the device
	b.ForgetInitiation("203.0.113.10:46000")
	b.ReplayInitiation("203.0.113.10:46000")
	select {
	case <-b.rx:
		t.Fatal("a forgotten initiation was replayed")
	default:
	}
}

// Hitting the cap must evict the oldest, not wipe the cache: the fresh entries are
// the ones a peer is about to ask for.
func TestInitiationCacheEvictsOldestNotEverything(t *testing.T) {
	b := listenBind(t)
	now := time.Now()
	for i := 0; i < initCacheMax; i++ {
		ap := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), 4000)
		b.recentInit[ap] = cachedInit{pkt: fakeInit(), at: now.Add(-time.Duration(i) * time.Millisecond)}
	}
	newer := &net.UDPAddr{IP: net.ParseIP("198.51.100.1").To4(), Port: 4000}
	b.Ingest(fakeInit(), newer)

	if len(b.recentInit) != initCacheMax {
		t.Fatalf("cache size %d after overflow, want %d (the cache was wiped instead of trimmed)", len(b.recentInit), initCacheMax)
	}
	// The freshest pre-existing entry must survive an overflow that only needs to
	// discard one.
	fresh := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 1}), 4000)
	if _, ok := b.recentInit[fresh]; !ok {
		t.Fatal("the newest cached initiation was evicted to make room")
	}
	if _, ok := b.recentInit[netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(initCacheMax)}), 4000)]; ok {
		t.Fatal("the oldest initiation survived while a fresher one went")
	}
}

// Once the device has answered an initiation, the copy in the cache is spent.
func TestSendResponseForgetsInitiation(t *testing.T) {
	b := listenBind(t)
	from := &net.UDPAddr{IP: net.ParseIP("203.0.113.11").To4(), Port: 47000}
	b.Ingest(fakeInit(), from)
	if len(b.recentInit) != 1 {
		t.Fatalf("initiation not cached: %d", len(b.recentInit))
	}
	// Route the write into a sink: the address is unreachable from here and the
	// behaviour under test is the cache, not the socket.
	b.SetSender(func([]byte, *net.UDPAddr) error { return nil })
	ep, err := b.ParseEndpoint("203.0.113.11:47000")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resp := make([]byte, 92)
	resp[0] = 2 // Handshake Response
	if err := b.Send([][]byte{resp}, ep); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(b.recentInit) != 0 {
		t.Fatalf("initiation kept after the device answered it: %d", len(b.recentInit))
	}
}
