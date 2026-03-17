package radius

import (
	"context"
	"net"
	"time"
)

// RadClient is a simple UDP RADIUS client.
//
// It encodes requests, sends them to the configured server, reads a reply, and
// validates the reply authenticator using the shared secret.
type RadClient struct {
	secret  string
	server  string
	timeout time.Duration
}

const sendTimeout time.Duration = 2 * time.Second
const bufSize int = 4096

// NewRadClient constructs a client for a server address (for example "host:1812")
// and a shared secret.
func NewRadClient(server string, secret string) *RadClient {
	return &RadClient{secret: secret, server: server}
}

// SetTimeout sets the fallback timeout used by Send/SendContext when the context
// has no deadline.
func (c *RadClient) SetTimeout(t time.Duration) {
	c.timeout = t
}

// SendContext sends a RADIUS packet using the provided context, allowing callers
// to control cancellation and deadlines. For most callers, use Send, which
// wraps this with context.Background().
func (c *RadClient) SendContext(ctx context.Context, request *Packet) (*Packet, error) {
	buf, err := request.Encode()
	if err != nil {
		return nil, err
	}

	requestAuth := make([]byte, 16)
	copy(requestAuth, request.Authenticator[:])

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", c.server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if udpConn, ok := conn.(*net.UDPConn); ok {
		udpConn.SetWriteBuffer(bufSize)
		udpConn.SetReadBuffer(bufSize)
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = sendTimeout
	}

	// Prefer context deadline if present; otherwise fall back to client timeout.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	// read answer (n bytes)
	b := make([]byte, bufSize)
	n, err := conn.Read(b)
	if err != nil {
		return nil, err
	}

	reply, err := DecodeReply(c.secret, b[:n], requestAuth)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// Send is a convenience wrapper around SendContext that uses context.Background().
func (c *RadClient) Send(request *Packet) (*Packet, error) {
	return c.SendContext(context.Background(), request)
}

// NewRequest constructs a new request packet with the given code using the
// client's shared secret.
func (c *RadClient) NewRequest(code PacketCode) *Packet {
	request := Request(code, c.secret)
	return request
}
