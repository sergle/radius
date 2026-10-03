package radius

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// startLegacyServer answers every request with an Access-Accept that has no Message-Authenticator.
func startLegacyServer(t *testing.T, secret string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, maxPacketLen)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < packetHeaderLen {
				continue
			}
			reply := make([]byte, packetHeaderLen)
			reply[0] = byte(AccessAccept)
			reply[1] = buf[1]
			binary.BigEndian.PutUint16(reply[2:4], packetHeaderLen)
			h := md5.New()
			h.Write(reply[:4])
			h.Write(buf[4:packetHeaderLen])
			h.Write([]byte(secret))
			copy(reply[4:], h.Sum(nil))
			conn.WriteToUDP(reply, addr)
		}
	}()
	return conn.LocalAddr().String()
}

// Blast-RADIUS: RadClient rejects Access-* replies without Message-Authenticator unless opted out.
func TestRadClientRequiresMessageAuthenticator(t *testing.T) {
	const secret = "testing123"
	client := NewRadClient(startLegacyServer(t, secret), secret)
	client.SetTimeout(time.Second)

	if _, err := client.Send(client.NewAccessRequest()); !errors.Is(err, ErrMessageAuthenticatorMissing) {
		t.Fatalf("default: got %v, want %v", err, ErrMessageAuthenticatorMissing)
	}

	client.SetRequireMessageAuthenticator(false)
	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("opted out: %v", err)
	}
	if reply.Code != AccessAccept {
		t.Fatalf("opted out: got %v, want Access-Accept", reply.Code)
	}
}
