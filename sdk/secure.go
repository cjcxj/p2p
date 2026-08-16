package p2p

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"p2p/core/protocol"
)

// dataKeyLen is the length of the per-pair ChaCha20-Poly1305 key.
const dataKeyLen = 32

// newDataKey generates this session's ephemeral X25519 key pair. The public
// half is sent in signaling candidates; the private half never leaves the
// session.
func newDataKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// dataPublicHex renders the session's X25519 public key for signaling.
func dataPublicHex(priv *ecdh.PrivateKey) string {
	if priv == nil {
		return ""
	}
	return hex.EncodeToString(priv.PublicKey().Bytes())
}

// parsePeerPublicKey decodes a hex-encoded X25519 public key from a
// signaling candidate.
func parsePeerPublicKey(pubHex string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

// deriveDataKey turns the raw X25519 shared secret into a per-pair AEAD key.
// The two peer IDs are sorted so both sides derive the same key.
func deriveDataKey(shared []byte, room string, a, b protocol.PeerID) ([]byte, error) {
	x, y := a.String(), b.String()
	if x > y {
		x, y = y, x
	}
	info := "p2p-data-v1:" + room + ":" + x + ":" + y
	return hkdf.Key(sha256.New, shared, nil, info, dataKeyLen)
}

// sealData encrypts a mesh frame for one peer. The returned payload is
// nonce || ciphertext+tag; the nonce is random per packet so UDP reordering
// does not break decryption.
func sealData(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// openData decrypts a payload produced by sealData. It returns an error for
// malformed or tampered payloads.
func openData(key, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("p2p: short encrypted payload")
	}
	nonce := payload[:aead.NonceSize()]
	return aead.Open(nil, nonce, payload[aead.NonceSize():], nil)
}

// negotiateDataKey derives the per-pair data-plane key from the peer's
// candidate public key. It returns nil when either side does not advertise
// a key or the exchange fails, in which case the session uses plaintext
// fallback (compatible with older peers).
func (s *Session) negotiateDataKey(peer protocol.PeerID, pubHex string) []byte {
	if s.x25519 == nil || pubHex == "" {
		return nil
	}
	pub, err := parsePeerPublicKey(pubHex)
	if err != nil {
		return nil
	}
	shared, err := s.x25519.ECDH(pub)
	if err != nil {
		return nil
	}
	key, err := deriveDataKey(shared, s.room, s.id, peer)
	if err != nil {
		return nil
	}
	return key
}
