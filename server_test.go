package radius

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const serverStopTimeout = 2 * time.Second

func TestServerAddrBeforeListen(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	if a := srv.Addr(); a != nil {
		t.Fatalf("Addr before Listen = %v, want nil", a)
	}
}

func TestServerStopBeforeListen(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	srv.Stop()
	srv.Stop()
	if err := srv.ListenAndServe(); !errors.Is(err, ErrServerStopped) {
		t.Fatalf("ListenAndServe after Stop = %v, want ErrServerStopped", err)
	}
}

func TestServerServeBeforeListen(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	if err := srv.Serve(); err == nil {
		t.Fatal("Serve before Listen succeeded, want error")
	}
}

func TestServerListenTwice(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	startTestServer(t, srv)
	if err := srv.Listen(); err == nil {
		t.Fatal("second Listen succeeded, want error")
	}
}

// Run under -race: Addr and Stop must not race with ListenAndServe.
func TestServerConcurrentAddrStop(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.Addr()
		}()
	}
	wg.Wait()
	srv.Stop()
	srv.Stop()

	select {
	case <-done:
	case <-time.After(serverStopTimeout):
		t.Fatal("server did not stop in time")
	}
}

func TestServerStopUnblocksServe(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", &radiusService{})
	addr, done := startTestServer(t, srv)

	client := NewRadClient(addr, "secret")
	client.SetTimeout(serverStopTimeout)
	if _, err := client.Send(client.NewAccessRequest()); err != nil {
		t.Fatalf("send: %v", err)
	}

	srv.Stop()
	select {
	case <-done:
	case <-time.After(serverStopTimeout):
		t.Fatal("server did not stop in time")
	}
}

// noReplyTimeout bounds the wait for a reply the server is expected to drop.
const noReplyTimeout = 300 * time.Millisecond

func acceptAll(ctx context.Context, request *Packet) *Packet { return request.ReplyAccept() }

// Blast-RADIUS: an Access-Request with Proxy-State but no Message-Authenticator is dropped by default.
func TestServerLimitProxyState(t *testing.T) {
	const secret = "testing123"
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(acceptAll))
	addr, _ := startTestServer(t, srv)
	proxyState := AVP{Type: AttrProxyState, Value: []byte("ps")}

	if _, err := exchangeRaw(t, addr, rawAccessRequest(1, proxyState), noReplyTimeout); err == nil {
		t.Error("Proxy-State without Message-Authenticator got a reply")
	}
	if _, err := exchangeRaw(t, addr, rawAccessRequest(2), noReplyTimeout); err != nil {
		t.Errorf("no Proxy-State, no Message-Authenticator: %v", err)
	}

	client := NewRadClient(addr, secret)
	client.SetTimeout(noReplyTimeout)
	req := client.NewAccessRequest()
	req.AddAVP(proxyState)
	if _, err := client.Send(req); err != nil {
		t.Errorf("Proxy-State with Message-Authenticator: %v", err)
	}
}

func TestServerLimitProxyStateOptOut(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "testing123", HandlerFunc(acceptAll))
	srv.SetLimitProxyState(false)
	addr, _ := startTestServer(t, srv)

	req := rawAccessRequest(1, AVP{Type: AttrProxyState, Value: []byte("ps")})
	if _, err := exchangeRaw(t, addr, req, noReplyTimeout); err != nil {
		t.Errorf("Proxy-State without Message-Authenticator, limit off: %v", err)
	}
}

func TestServerRequireMessageAuthenticator(t *testing.T) {
	const secret = "testing123"
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(acceptAll))
	srv.SetRequireMessageAuthenticator(true)
	addr, _ := startTestServer(t, srv)

	if _, err := exchangeRaw(t, addr, rawAccessRequest(1), noReplyTimeout); err == nil {
		t.Error("Access-Request without Message-Authenticator got a reply")
	}

	client := NewRadClient(addr, secret)
	client.SetTimeout(noReplyTimeout)
	if _, err := client.Send(client.NewAccessRequest()); err != nil {
		t.Errorf("Access-Request with Message-Authenticator: %v", err)
	}
}

// A reply built without Reply() still gets the request's Identifier, Secret and Authenticator.
func TestServerBareReply(t *testing.T) {
	const secret = "testing123"
	const msg = "welcome"
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		return &Packet{Code: AccessAccept, AVPs: []AVP{{Type: AttrReplyMessage, Value: []byte(msg)}}}
	}))
	addr, _ := startTestServer(t, srv)

	client := NewRadClient(addr, secret)
	client.SetTimeout(noReplyTimeout)
	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if reply.Code != AccessAccept {
		t.Errorf("Code = %v, want AccessAccept", reply.Code)
	}
	if a := reply.GetAVP(AttrReplyMessage); a == nil || string(a.Value) != msg {
		t.Errorf("Reply-Message = %v, want %q", a, msg)
	}
}

// Tunnel-Password added to a Reply() is encrypted with the request authenticator.
func TestServerReplyTunnelPassword(t *testing.T) {
	const secret = "testing123"
	const pw = "vlan-secret"
	const tag = 1
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		reply := request.ReplyAccept()
		if err := reply.AddTunnelPassword(tag, pw); err != nil {
			t.Errorf("AddTunnelPassword: %v", err)
		}
		return reply
	}))
	addr, _ := startTestServer(t, srv)

	client := NewRadClient(addr, secret)
	client.SetTimeout(noReplyTimeout)
	reply, err := client.Send(client.NewAccessRequest())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotTag, got, ok := reply.GetTunnelPassword(); !ok || gotTag != tag || got != pw {
		t.Errorf("GetTunnelPassword = %d, %q, %v; want %d, %q, true", gotTag, got, ok, tag, pw)
	}
}
