package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestL7EncodeParse(t *testing.T) {
	body := []byte("hello")
	enc := l7Encode(l7Datagram, body)
	kind, decoded, ok := l7Parse(enc)
	if !ok {
		t.Fatal("l7Parse failed")
	}
	if kind != l7Datagram {
		t.Fatalf("kind = %d, want %d", kind, l7Datagram)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("body = %q, want %q", decoded, body)
	}

	if _, _, ok := l7Parse([]byte("not-l7")); ok {
		t.Fatal("non-L7 data should not parse")
	}
}

func TestL7DatagramDispatch(t *testing.T) {
	l := &L7{}
	var got []byte
	l.OnDatagram(func(peerID string, data []byte) {
		got = append([]byte(nil), data...)
	})
	if !l.handleData("peer", l7Encode(l7Datagram, []byte("hi"))) {
		t.Fatal("datagram not handled")
	}
	if string(got) != "hi" {
		t.Fatalf("datagram = %q, want %q", got, "hi")
	}
}

func TestL7PubSubDispatch(t *testing.T) {
	l := &L7{subs: make(map[string][]func(peerID string, data []byte))}
	var got []byte
	l.Subscribe("topic", func(peerID string, data []byte) {
		got = append([]byte(nil), data...)
	})

	body := make([]byte, 2+5+2)
	binary.BigEndian.PutUint16(body[0:2], 5)
	copy(body[2:], "topic")
	copy(body[7:], "ok")

	if !l.handleData("peer", l7Encode(l7PubSub, body)) {
		t.Fatal("pubsub not handled")
	}
	if string(got) != "ok" {
		t.Fatalf("pubsub payload = %q, want %q", got, "ok")
	}
}

func TestL7PongDispatch(t *testing.T) {
	l := &L7{pendingPings: make(map[uint64]chan time.Duration)}
	id := uint64(7)
	ch := make(chan time.Duration, 1)
	l.pendingPings[id] = ch

	sent := time.Now().Add(-10 * time.Millisecond)
	body := make([]byte, 16)
	binary.BigEndian.PutUint64(body[0:8], uint64(sent.UnixNano()))
	binary.BigEndian.PutUint64(body[8:16], id)

	if !l.handleData("peer", l7Encode(l7Pong, body)) {
		t.Fatal("pong not handled")
	}
	select {
	case rtt := <-ch:
		if rtt <= 0 {
			t.Fatalf("rtt = %v, want > 0", rtt)
		}
	default:
		t.Fatal("no rtt delivered")
	}
}
