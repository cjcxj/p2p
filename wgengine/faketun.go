package wgengine

import (
	"net"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// FakeTUN is an in-memory tun.Device that exercises the WireGuard data path
// without administrator rights. Inject plays the part of the OS delivering an
// outbound packet to the interface; Outbound yields what the device writes back.
type FakeTUN struct {
	inj    chan []byte
	out    chan []byte
	events chan tun.Event
	mtu    int
	once   sync.Once
	closed chan struct{}

	// raw hands Write's slice to the reader instead of a copy, so benchmarks
	// count WireGuard's allocations rather than the test double's. Only safe for
	// consumers that look at the packet before the device recycles the buffer.
	// Atomic because the device's read loop reads it on every Write while a test
	// turns it on from its own goroutine.
	raw atomic.Bool
}

var _ tun.Device = (*FakeTUN)(nil)

// SetRaw switches Write to hand out the device's own buffer instead of a copy.
func (f *FakeTUN) SetRaw(on bool) { f.raw.Store(on) }

func NewFakeTUN(mtu int) *FakeTUN {
	if mtu <= 0 {
		mtu = 1420
	}
	return &FakeTUN{
		inj:    make(chan []byte, 256),
		out:    make(chan []byte, 256),
		events: make(chan tun.Event),
		mtu:    mtu,
		closed: make(chan struct{}),
	}
}

func (f *FakeTUN) File() *os.File           { return nil }
func (f *FakeTUN) MTU() (int, error)        { return f.mtu, nil }
func (f *FakeTUN) Name() (string, error)    { return "p2p-fake", nil }
func (f *FakeTUN) Events() <-chan tun.Event { return f.events }
func (f *FakeTUN) BatchSize() int           { return 1 }
func (f *FakeTUN) Outbound() <-chan []byte  { return f.out }

// Inject queues an IP packet as if the kernel had routed it to the interface.
func (f *FakeTUN) Inject(pkt []byte) bool {
	b := append([]byte(nil), pkt...)
	select {
	case f.inj <- b:
		return true
	case <-f.closed:
		return false
	}
}

func (f *FakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-f.inj:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *FakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		pkt := buf[offset:]
		if !f.raw.Load() {
			pkt = append([]byte(nil), pkt...)
		}
		select {
		case f.out <- pkt:
			written++
		case <-f.closed:
			return written, net.ErrClosed
		}
	}
	return written, nil
}

func (f *FakeTUN) Close() error {
	f.once.Do(func() {
		close(f.closed)
		close(f.events)
	})
	return nil
}
