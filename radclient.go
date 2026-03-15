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

	// In v2, we dial once per Send for simplicity, but we've removed the redundant ResolveUDPAddr
	// and narrowed the Dial to net.Dial for better versatility.
	conn, err := net.Dial("udp", c.server)
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

	conn.SetDeadline(time.Now().Add(timeout * time.Second))

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
