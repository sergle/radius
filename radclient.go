package radius

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"time"
)

const (
	// default when neither SetTimeout nor a ctx deadline is set
	sendTimeout = 2 * time.Second

	// backoff before retransmitting after a send/receive error, doubling up to retryBackoffMax
	retryBackoff    = 100 * time.Millisecond
	retryBackoffMax = time.Second
)

// RadClient is a simple UDP RADIUS client.
//
// It encodes requests, sends them to the configured server, reads a reply, and
// validates the reply authenticator using the shared secret. Replies with a
// wrong Identifier or code, or failing verification, are skipped while waiting. With
// SetRetries the unchanged request is retransmitted (RFC 5080 section 2.2.1).
type RadClient struct {
	secret  string
	server  string
	timeout time.Duration

	retries       int           // retransmissions after the first send
	retryInterval time.Duration // wait before each retransmission; 0: retransmit only on error

	allowMissingMA bool // Access-* replies may omit Message-Authenticator
}

// NewRadClient constructs a client for a server address (for example "host:1812")
// and a shared secret.
func NewRadClient(server string, secret string) *RadClient {
	return &RadClient{secret: secret, server: server}
}

// SetTimeout sets the fallback timeout used by Send/SendContext when the context
// has no deadline. It bounds the whole exchange, including retransmissions.
func (c *RadClient) SetTimeout(t time.Duration) {
	c.timeout = t
}

// SetRetries sets how many times a request is retransmitted (default 0): after
// each retry interval without a reply, or after a send/receive error with
// exponential backoff (100ms up to 1s). Retransmissions reuse the same
// Identifier and Authenticator and stop at the context deadline or timeout.
func (c *RadClient) SetRetries(n int) {
	c.retries = max(n, 0)
}

// SetRetryInterval sets how long to wait for a reply before retransmitting.
// Zero (default) waits until the deadline and retransmits only on error.
func (c *RadClient) SetRetryInterval(d time.Duration) {
	c.retryInterval = d
}

// SetRequireMessageAuthenticator controls whether Access-* replies must carry a
// valid Message-Authenticator (default true, RFC 3579 / Blast-RADIUS mitigation).
// Disable it only for legacy servers that do not send one.
func (c *RadClient) SetRequireMessageAuthenticator(require bool) {
	c.allowMissingMA = !require
}

// SendContext sends a RADIUS packet using the provided context, allowing callers
// to control cancellation and deadlines. For most callers, use Send, which
// wraps this with context.Background().
//
// If no valid reply arrives, the last verification error of a skipped reply is
// returned, or else the timeout or context error.
func (c *RadClient) SendContext(ctx context.Context, request *Packet) (*Packet, error) {
	buf, err := request.Encode()
	if err != nil {
		return nil, err
	}

	// the Authenticator sent, which may differ from request.Authenticator (computed or generated)
	requestAuth := buf[4:packetHeaderLen]

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", c.server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Unblock a pending read on cancellation.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Prefer context deadline if present; otherwise fall back to client timeout.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(cmp.Or(c.timeout, sendTimeout))
	}
	conn.SetWriteDeadline(deadline)

	opts := DecodeOptions{RequireMessageAuthenticator: !c.allowMissingMA}
	b := make([]byte, maxPacketLen)
	var lastErr error // last reply that failed verification
	backoff := retryBackoff
	for attempt := 0; ; attempt++ {
		// Without a retry interval, wait for the reply until the deadline and resend only on error.
		readDeadline := deadline
		if next := time.Now().Add(c.retryInterval); c.retryInterval > 0 && attempt < c.retries && next.Before(deadline) {
			readDeadline = next
		}
		conn.SetReadDeadline(readDeadline)

		_, err := conn.Write(buf)
		for err == nil {
			var n int
			if n, err = conn.Read(b); err != nil {
				break
			}
			if n < packetHeaderLen || b[1] != request.Identifier {
				continue
			}
			reply, derr := DecodeReplyWithOptions(c.secret, b[:n], requestAuth, &opts)
			if derr == nil && !reply.Code.answers(request.Code) {
				derr = fmt.Errorf("%w %v in reply to %v", ErrUnexpectedCode, reply.Code, request.Code)
			}
			if derr != nil {
				lastErr = derr
				continue
			}
			return reply, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt >= c.retries || !time.Now().Before(deadline) {
			return nil, cmp.Or(lastErr, err)
		}
		// a timed-out attempt has already waited; back off only after an error
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			continue
		}
		if time.Until(deadline) <= backoff {
			return nil, cmp.Or(lastErr, err)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff = min(2*backoff, retryBackoffMax)
	}
}

// Send is a convenience wrapper around SendContext that uses context.Background().
func (c *RadClient) Send(request *Packet) (*Packet, error) {
	return c.SendContext(context.Background(), request)
}

// NewRequest constructs a new request packet with the given code using the
// client's shared secret.
func (c *RadClient) NewRequest(code PacketCode) *Packet {
	return Request(code, c.secret)
}

// NewAccessRequest constructs an Access-Request packet.
func (c *RadClient) NewAccessRequest() *Packet { return c.NewRequest(AccessRequest) }

// NewAccountingRequest constructs an Accounting-Request packet.
func (c *RadClient) NewAccountingRequest() *Packet { return c.NewRequest(AccountingRequest) }

// NewDisconnectRequest constructs a Disconnect-Request (RFC 3576) packet.
func (c *RadClient) NewDisconnectRequest() *Packet { return c.NewRequest(DisconnectRequest) }

// NewCoARequest constructs a Change-of-Authorization Request (RFC 3576) packet.
func (c *RadClient) NewCoARequest() *Packet { return c.NewRequest(CoARequest) }

// NewStatusServer constructs a Status-Server (RFC 5997) packet.
func (c *RadClient) NewStatusServer() *Packet { return c.NewRequest(StatusServer) }
