package radius

import (
	"net"
	"time"
)

type RadClient struct {
	secret  string
	server  string
	timeout time.Duration
}

const sendTimeout time.Duration = 2
const bufSize int = 4096

func NewRadClient(server string, secret string) *RadClient {
	return &RadClient{secret: secret, server: server}
}

func (c *RadClient) SetTimeout(t time.Duration) {
	c.timeout = t
}

func (c *RadClient) Send(request *Packet) (*Packet, error) {
	buf, err := request.Encode()
	if err != nil {
		return nil, err
	}

	request_auth := make([]byte, 16)
	copy(request_auth, request.Authenticator[:])

	addr, err := net.ResolveUDPAddr("udp", c.server)
	if err != nil {
		return nil, err
	}

	// TODO reuse connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	timeout := c.timeout
	if timeout == 0 {
		timeout = sendTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout * time.Second))
	conn.SetWriteBuffer(bufSize)
	conn.SetReadBuffer(bufSize)

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	// read answer (n bytes)
	b := make([]byte, bufSize)
	n, _, err := conn.ReadFrom(b)
	if err != nil {
		// TODO ignore timeouts
		return nil, err
	}

	reply, err := DecodeReply(c.secret, b[:n], request_auth)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// create empty packet
func (c *RadClient) NewRequest(code PacketCode) *Packet {
	request := Request(code, c.secret)
	return request
}
