package stun

import (
	"errors"
	"net"
	"time"
)

// Client performs STUN binding requests over a caller-supplied packet
// connection. Supplying the connection lets the client be used behind a real
// NAT.
type Client struct {
	Conn   net.PacketConn
	Server *net.UDPAddr
	// Retries is the number of times each request is re-sent (default 2).
	Retries int
	// Timeout is the per-request read deadline (default 2s).
	Timeout time.Duration
}

// BindRequest sends a binding request (optionally with a CHANGE-REQUEST) and
// waits for the matching response. It returns the response and the source
// address it arrived from.
func (c *Client) BindRequest(changeIP, changePort bool) (*Message, *net.UDPAddr, error) {
	req := NewBindingRequest()
	if changeIP || changePort {
		req.SetChangeRequest(changeIP, changePort)
	}
	req.AddSoftware("p2p")

	retries := c.Retries
	if retries <= 0 {
		retries = 2
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if _, err := c.Conn.WriteTo(req.Encode(), c.Server); err != nil {
			return nil, nil, err
		}
		deadline := time.Now().Add(timeout)
		if dc, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			dc.SetReadDeadline(deadline)
		}
		for {
			buf := make([]byte, 2048)
			n, src, err := c.Conn.ReadFrom(buf)
			if err != nil {
				if isTimeout(err) {
					break // retry
				}
				return nil, nil, err
			}
			if n < HeaderLength {
				continue
			}
			msg, err := Decode(buf[:n])
			if err != nil || msg.TID != req.TID {
				continue
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				ua = nil
			}
			return msg, ua, nil
		}
	}
	return nil, nil, errors.New("stun: no response")
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// BindOnce is a convenience wrapper for a single plain binding request.
func (c *Client) BindOnce() (*Message, *net.UDPAddr, error) {
	return c.BindRequest(false, false)
}
