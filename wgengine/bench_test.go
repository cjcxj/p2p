package wgengine

import (
	"sync/atomic"
	"testing"
	"time"
)

// inject shares pkt with the device instead of copying it the way Inject does.
// Benchmarks reuse one immutable packet, so the copy would only add allocations
// the real TUN driver does not pay.
func (f *FakeTUN) inject(pkt []byte) bool {
	select {
	case f.inj <- pkt:
		return true
	case <-f.closed:
		return false
	}
}

// benchTunnel measures one IP packet travelling the whole tunnel: it enters tunA
// as a plain IP packet, crosses the punched UDP socket encrypted, and leaves tunB
// decrypted. Everything between the two fake interfaces is what the product pays
// per packet.
func benchTunnel(b *testing.B, size int) {
	b.ReportAllocs()
	p := established(b)
	p.tunB.SetRaw(true)
	pkt := echoRequest(vipA, vipB, size)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.tunA.inject(pkt) {
			b.Fatal("inject failed")
		}
		select {
		case <-p.tunB.Outbound():
		case <-time.After(10 * time.Second):
			b.Fatal("packet never crossed the tunnel")
		}
	}
	b.StopTimer()
}

// benchPipeline is the same path with the receiver running alongside the sender.
// A saturated tunnel drops datagrams like any UDP path does, so this reports what
// it actually delivered rather than insisting every offered packet arrives.
func benchPipeline(b *testing.B, size int) {
	b.ReportAllocs()
	p := established(b)
	p.tunB.SetRaw(true)
	pkt := echoRequest(vipA, vipB, size)

	var got atomic.Int64
	stop := make(chan struct{})
	drain := make(chan struct{})
	go func() {
		defer close(drain)
		for {
			select {
			case <-p.tunB.Outbound():
				got.Add(1)
			case <-stop:
				return
			}
		}
	}()

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.tunA.inject(pkt) {
			b.Fatal("inject failed")
		}
	}
	b.StopTimer()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	<-drain
	delivered := got.Load()
	if delivered < int64(b.N)/2 {
		b.Fatalf("only %d of %d packets crossed the tunnel", delivered, b.N)
	}
	b.ReportMetric(float64(delivered)/float64(b.N)*100, "%delivered")
}

func BenchmarkTunnel1420(b *testing.B) { benchTunnel(b, 1420) }
func BenchmarkTunnel512(b *testing.B)  { benchTunnel(b, 512) }

func BenchmarkPipeline1420(b *testing.B) { benchPipeline(b, 1420) }
func BenchmarkPipeline512(b *testing.B)  { benchPipeline(b, 512) }

// TestTunnelSustained pushes at the tunnel for a fixed window and reports the
// packet rate it kept up, which is the number iperf3 over the interface sees.
func TestTunnelSustained(t *testing.T) {
	const window = 3 * time.Second
	for _, size := range []int{1420, 512} {
		p := established(t)
		p.tunB.SetRaw(true)
		pkt := echoRequest(vipA, vipB, size)

		var got atomic.Int64
		stop := make(chan struct{})
		drain := make(chan struct{})
		go func() {
			defer close(drain)
			for {
				select {
				case <-p.tunB.Outbound():
					got.Add(1)
				case <-stop:
					return
				}
			}
		}()

		var offered int64
		deadline := time.Now().Add(window)
		for time.Now().Before(deadline) {
			if !p.tunA.inject(pkt) {
				t.Fatal("inject failed")
			}
			offered++
		}
		elapsed := time.Since(deadline.Add(-window)).Seconds()
		time.Sleep(200 * time.Millisecond)
		close(stop)
		<-drain

		delivered := got.Load()
		mbit := float64(delivered) * float64(size) * 8 / elapsed / 1e6
		t.Logf("%d byte packets: offered %.0f pkt/s, delivered %.0f pkt/s (%.1f Mbit/s), dropped %.2f%%",
			size,
			float64(offered)/elapsed, float64(delivered)/elapsed, mbit,
			float64(offered-delivered)*100/float64(offered))
		if delivered == 0 {
			t.Fatalf("tunnel delivered nothing at size %d", size)
		}
	}
}
