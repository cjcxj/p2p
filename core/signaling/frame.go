// Package signaling implements a JSON-over-TCP coordination channel with
// length-prefixed frames.
package signaling

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"

	"p2p/core/protocol"
)

// maxFrame caps a single signaling frame at 1 MiB.
const maxFrame = 1 << 20

// WriteMsg serialises and sends a protocol message.
func WriteMsg(conn net.Conn, m protocol.Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("signaling: frame too large")
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(b)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// ReadMsg reads one protocol message.
func ReadMsg(conn net.Conn) (protocol.Message, error) {
	var m protocol.Message
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(hdr)
	if n > maxFrame {
		return m, errors.New("signaling: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return m, err
	}
	err := json.Unmarshal(buf, &m)
	return m, err
}
