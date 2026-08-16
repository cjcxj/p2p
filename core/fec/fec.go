// Package fec provides a minimal forward error correction primitive based on
// XOR parity. It is useful for real-time UDP flows where retransmission is
// too slow: one lost packet in a group can be reconstructed from the others
// and the parity packet.
package fec

import "errors"

// Encode computes one parity packet for a group of equal-length packets.
// The parity packet is the bitwise XOR of all input packets.
func Encode(packets [][]byte) ([]byte, error) {
	if len(packets) == 0 {
		return nil, errors.New("fec: no packets")
	}
	n := len(packets[0])
	for _, p := range packets {
		if len(p) != n {
			return nil, errors.New("fec: packet length mismatch")
		}
	}
	parity := make([]byte, n)
	for _, p := range packets {
		for i, b := range p {
			parity[i] ^= b
		}
	}
	return parity, nil
}

// Recover reconstructs the missing packet at missingIndex. packets must all
// have the same length; packets[missingIndex] is ignored and may be nil.
func Recover(packets [][]byte, missingIndex int, parity []byte) ([]byte, error) {
	if missingIndex < 0 || missingIndex >= len(packets) {
		return nil, errors.New("fec: bad missing index")
	}
	n := len(parity)
	for i, p := range packets {
		if i == missingIndex {
			continue
		}
		if len(p) != n {
			return nil, errors.New("fec: packet length mismatch")
		}
	}
	out := make([]byte, n)
	copy(out, parity)
	for i, p := range packets {
		if i == missingIndex {
			continue
		}
		for j, b := range p {
			out[j] ^= b
		}
	}
	return out, nil
}
