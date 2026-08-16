package fec

import (
	"bytes"
	"testing"
)

func TestEncodeRecover(t *testing.T) {
	packets := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("fec!!"),
	}
	parity, err := Encode(packets)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate losing packet index 1.
	lost := packets[1]
	packets[1] = nil
	got, err := Recover(packets, 1, parity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, lost) {
		t.Fatalf("recovered = %q, want %q", got, lost)
	}
}
