package radius

import (
	"context"
	"testing"
	"time"
)

func TestEndToEndRADIUS(t *testing.T) {
	secret := "shared-secret"
	// Use port 0 to let the OS choose a random available port
	addr := "127.0.0.1:0"

	// 1. Define Server Handler
	handler := HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		reply := request.Reply()
		if request.Code == AccessRequest {
			if request.GetUsername() == "testuser" && request.GetPassword() == "testpass" {
				reply.Code = AccessAccept
				reply.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("Welcome!")})
			} else {
				reply.Code = AccessReject
			}
		}
		return reply
	})

	// 2. Start Server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(addr, secret, handler)
	srv.ctx = ctx
	srv.cancel = cancel

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.ListenAndServe()
	}()

	// Wait for server to start and get the address
	var actualAddr string
	for i := 0; i < 10; i++ {
		if srv.conn != nil {
			actualAddr = srv.conn.LocalAddr().String()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if actualAddr == "" {
		t.Fatal("Server failed to start in time")
	}

	// 3. Client Interaction
	client := NewRadClient(actualAddr, secret)
	client.SetTimeout(2 * time.Second)

	t.Run("Valid Credentials", func(t *testing.T) {
		req := client.NewRequest(AccessRequest)
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("testuser")})
		req.AddPassword("testpass")

		reply, err := client.Send(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}

		if reply.Code != AccessAccept {
			t.Errorf("Expected Access-Accept, got %v", reply.Code)
		}

		msg := reply.GetAVP(AttrReplyMessage)
		if string(msg.Value) != "Welcome!" {
			t.Errorf("Expected 'Welcome!', got %s", string(msg.Value))
		}
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		req := client.NewRequest(AccessRequest)
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("testuser")})
		req.AddPassword("wrongpass")

		reply, err := client.Send(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}

		if reply.Code != AccessReject {
			t.Errorf("Expected Access-Reject, got %v", reply.Code)
		}
	})

	// 4. Test Server Stop (Context Cancellation)
	t.Run("Server Shutdown", func(t *testing.T) {
		cancel()
		time.Sleep(50 * time.Millisecond)

		// Try to send after shutdown
		req := client.NewRequest(AccessRequest)
		client.SetTimeout(1 * time.Second)
		_, err := client.Send(req)
		if err == nil {
			t.Error("Expected error sending to stopped server, got nil")
		}
	})
}
