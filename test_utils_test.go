package radius

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func ok(t *testing.T, b bool) {
	if !b {
		t.Helper()
		t.Fatal("fail")
	}
}

// startTestServer binds srv, serves it in the background and stops it on cleanup.
// The returned channel receives Serve's result.
func startTestServer(t *testing.T, srv *Server) (addr string, done <-chan error) {
	t.Helper()
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve() }()
	t.Cleanup(srv.Stop)
	return srv.Addr().String(), errCh
}

// rawAccessRequest builds an Access-Request by hand, without Message-Authenticator.
func rawAccessRequest(id uint8, avps ...AVP) []byte {
	return rawRequest(AccessRequest, id, avps...)
}

// rawRequest builds a request with a random authenticator by hand, without Message-Authenticator.
func rawRequest(code PacketCode, id uint8, avps ...AVP) []byte {
	b := make([]byte, packetHeaderLen, maxPacketLen)
	b[0] = byte(code)
	b[1] = id
	rand.Read(b[4:packetHeaderLen])
	for _, a := range avps {
		b = append(b, byte(a.Type), byte(2+len(a.Value)))
		b = append(b, a.Value...)
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

// exchangeRaw sends b to addr and returns the reply, or an error if none arrives within timeout.
func exchangeRaw(t *testing.T, addr string, b []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, maxPacketLen)
	n, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}
	return reply[:n], nil
}
