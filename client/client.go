package client

import (
	"net"
	"time"

	"github.com/sergle/radius"
)

type Client struct {
	secret string
	server string
}

const sendTimeout time.Duration = 2
const bufSize int = 4096

func NewClient(server string, secret string) *Client {
	return &Client{secret: secret, server: server}
}

func (c *Client) Send(request *radius.Packet) (*radius.Packet, error) {
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

	conn.SetDeadline(time.Now().Add(sendTimeout * time.Second))
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

	reply, err := radius.DecodeReply(c.secret, b[:n], request_auth)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// create empty packet
func (c *Client) NewRequest(code radius.PacketCode) *radius.Packet {
	request := radius.Request(code, c.secret)
	return request
}
