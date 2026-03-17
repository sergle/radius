package radius

import (
	"context"
	"net"
	"testing"
	"time"
)

func sendRadiusFromLocal(t *testing.T, localIP string, localPort int, serverAddr string, secret string, req *Packet) (*Packet, error) {
	t.Helper()

	buf, err := req.Encode()
	if err != nil {
		return nil, err
	}

	requestAuth := make([]byte, 16)
	copy(requestAuth, req.Authenticator[:])

	laddr := &net.UDPAddr{IP: net.ParseIP(localIP), Port: localPort}
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	b := make([]byte, 4096)
	n, err := conn.Read(b)
	if err != nil {
		return nil, err
	}

	reply, err := DecodeReply(secret, b[:n], requestAuth)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func TestServerClientList(t *testing.T) {
	clients := NewClientList([]Client{
		NewClient("127.0.0.1:18120", "secret-1"),
		NewClient("127.0.0.1:18121", "secret-2"),
	})

	handler := HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		reply := request.Reply()
		reply.Code = AccessAccept
		return reply
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServerWithClientList("127.0.0.1:0", clients, handler)
	srv.ctx = ctx
	srv.cancel = cancel

	errChan := make(chan error, 1)
	go func() { errChan <- srv.ListenAndServe() }()

	var actualAddr string
	for i := 0; i < 20; i++ {
		if srv.conn != nil {
			actualAddr = srv.conn.LocalAddr().String()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if actualAddr == "" {
		t.Fatal("server failed to start in time")
	}

	t.Run("known client 127.0.0.1", func(t *testing.T) {
		req := Request(AccessRequest, "secret-1")
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("u1")})

		reply, err := sendRadiusFromLocal(t, "127.0.0.1", 18120, actualAddr, "secret-1", req)
		if err != nil {
			t.Fatalf("send failed: %v", err)
		}
		if reply.Code != AccessAccept {
			t.Fatalf("expected Access-Accept, got %v", reply.Code)
		}
	})

	t.Run("known client 127.0.0.1 (different port)", func(t *testing.T) {
		req := Request(AccessRequest, "secret-2")
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("u2")})

		reply, err := sendRadiusFromLocal(t, "127.0.0.1", 18121, actualAddr, "secret-2", req)
		if err != nil {
			t.Fatalf("send failed: %v", err)
		}
		if reply.Code != AccessAccept {
			t.Fatalf("expected Access-Accept, got %v", reply.Code)
		}
	})

	t.Run("unknown client is dropped", func(t *testing.T) {
		req := Request(AccessRequest, "does-not-matter")
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("u3")})

		_, err := sendRadiusFromLocal(t, "127.0.0.1", 18122, actualAddr, "does-not-matter", req)
		if err == nil {
			t.Fatalf("expected timeout/error for unknown client, got nil")
		}
	})

	cancel()
	srv.Stop()
	select {
	case <-errChan:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

