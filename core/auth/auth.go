// Package auth implements mutual authentication between a p2p client and the
// signaling server using HMAC-SHA256 challenge-response with a pre-shared
// secret (or a per-user password).
//
// Both sides prove knowledge of a shared credential key:
//
//   credKey  = HMAC(secret, "p2p-auth-v1"[:user])
//   clientProof = HMAC(credKey, "client:<clientNonce>:<serverNonce>")
//   serverProof = HMAC(credKey, "server:<serverNonce>:<clientNonce>")
//
// The client proves itself to the server (server auth) and the server proves
// itself to the client (client auth), so a rogue server cannot impersonate a
// real one and an unauthenticated client cannot join.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const ns = "p2p-auth-v1"

// CredKey derives the shared credential key from a secret and an optional
// username. Per-user keys differ so users can be told apart.
func CredKey(secret, user string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	if user != "" {
		m.Write([]byte(ns + ":" + user))
	} else {
		m.Write([]byte(ns))
	}
	return m.Sum(nil)
}

// Proof computes an HMAC proof for one side of the handshake. role is
// "client" or "server".
func Proof(key []byte, role, clientNonce, serverNonce string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(role + ":" + clientNonce + ":" + serverNonce))
	return hex.EncodeToString(m.Sum(nil))
}

// RandomNonce returns a random hex nonce.
func RandomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Equal compares two proofs in constant time.
func Equal(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
