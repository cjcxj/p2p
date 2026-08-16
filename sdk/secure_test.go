package p2p

import (
	"bytes"
	"testing"

	"p2p/core/protocol"
)

func TestSealOpenData(t *testing.T) {
	key := make([]byte, dataKeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	plain := []byte("hello mesh")

	sealed, err := sealData(key, plain)
	if err != nil {
		t.Fatalf("sealData: %v", err)
	}
	opened, err := openData(key, sealed)
	if err != nil {
		t.Fatalf("openData: %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("round trip mismatch: got %q want %q", opened, plain)
	}

	// Tampering must be rejected.
	sealed[0] ^= 0xff
	if _, err := openData(key, sealed); err == nil {
		t.Fatal("openData accepted a tampered payload")
	}
}

func TestSealOpenE2E(t *testing.T) {
	key := make([]byte, dataKeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	plain := []byte("end-to-end secret")

	sealed, err := sealE2E(key, plain)
	if err != nil {
		t.Fatalf("sealE2E: %v", err)
	}
	dec, marked, err := openE2E(key, sealed)
	if err != nil {
		t.Fatalf("openE2E: %v", err)
	}
	if !marked {
		t.Fatal("openE2E did not mark payload as encrypted")
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("e2e round trip mismatch: got %q want %q", dec, plain)
	}

	// Plain payloads are not marked.
	_, marked, err = openE2E(key, plain)
	if err != nil {
		t.Fatalf("openE2E plain: %v", err)
	}
	if marked {
		t.Fatal("plain payload was marked as e2e")
	}
}

func TestDeriveDataKeySymmetric(t *testing.T) {
	a, err := newDataKey()
	if err != nil {
		t.Fatalf("newDataKey A: %v", err)
	}
	b, err := newDataKey()
	if err != nil {
		t.Fatalf("newDataKey B: %v", err)
	}
	room := "demo"
	idA := protocol.NewPeerID()
	idB := protocol.NewPeerID()

	sharedA, err := a.ECDH(b.PublicKey())
	if err != nil {
		t.Fatalf("ECDH A: %v", err)
	}
	sharedB, err := b.ECDH(a.PublicKey())
	if err != nil {
		t.Fatalf("ECDH B: %v", err)
	}

	keyA, err := deriveDataKey(sharedA, room, idA, idB)
	if err != nil {
		t.Fatalf("deriveDataKey A: %v", err)
	}
	keyB, err := deriveDataKey(sharedB, room, idB, idA)
	if err != nil {
		t.Fatalf("deriveDataKey B: %v", err)
	}
	if !bytes.Equal(keyA, keyB) {
		t.Fatal("both sides derived different data-plane keys")
	}
}
