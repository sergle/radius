package radius

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// sendRaw writes b to addr without waiting for a reply.
func sendRaw(t *testing.T, addr string, b []byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// blockingHandler signals started for each request and blocks until release is closed.
func blockingHandler(started chan<- struct{}, release <-chan struct{}, returned *atomic.Int32) HandlerFunc {
	return func(ctx context.Context, request *Packet) *Packet {
		started <- struct{}{}
		<-release
		returned.Add(1)
		return nil
	}
}

func TestServerServeReturnsErrServerStopped(t *testing.T) {
	srv := NewServer("127.0.0.1:0", "secret", HandlerFunc(acceptAll))
	_, done := startTestServer(t, srv)

	srv.Stop()
	select {
	case err := <-done:
		if !errors.Is(err, ErrServerStopped) {
			t.Fatalf("Serve after Stop = %v, want ErrServerStopped", err)
		}
	case <-time.After(serverStopTimeout):
		t.Fatal("server did not stop in time")
	}
}

func TestServerStopWaitsForHandlers(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var returned atomic.Int32
	srv := NewServer("127.0.0.1:0", "secret", blockingHandler(started, release, &returned))
	addr, _ := startTestServer(t, srv)

	sendRaw(t, addr, rawAccessRequest(1))
	<-started

	stopped := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a handler was running")
	case <-time.After(noReplyTimeout):
	}

	close(release)
	select {
	case <-stopped:
	case <-time.After(serverStopTimeout):
		t.Fatal("Stop did not return after the handler finished")
	}
	if returned.Load() != 1 {
		t.Fatalf("handlers returned = %d, want 1", returned.Load())
	}
}

func TestServerMaxConcurrent(t *testing.T) {
	const limit = 1
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var returned atomic.Int32
	srv := NewServer("127.0.0.1:0", "secret", blockingHandler(started, release, &returned))
	if err := srv.SetMaxConcurrent(limit); err != nil {
		t.Fatalf("SetMaxConcurrent before Serve: %v", err)
	}
	addr, _ := startTestServer(t, srv)

	sendRaw(t, addr, rawAccessRequest(1))
	sendRaw(t, addr, rawAccessRequest(2))
	<-started
	select {
	case <-started:
		t.Fatal("second handler started above the concurrency limit")
	case <-time.After(noReplyTimeout):
	}

	close(release)
	select {
	case <-started:
	case <-time.After(serverStopTimeout):
		t.Fatal("second handler did not start after the first finished")
	}
}

func TestServerSetMaxConcurrentAfterServe(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var returned atomic.Int32
	srv := NewServer("127.0.0.1:0", "secret", blockingHandler(started, release, &returned))
	defer close(release)
	addr, _ := startTestServer(t, srv)

	// a running handler proves Serve has started
	sendRaw(t, addr, rawAccessRequest(1))
	<-started
	if err := srv.SetMaxConcurrent(1); err == nil {
		t.Fatal("SetMaxConcurrent after Serve succeeded, want error")
	}
}

func TestServerPerRequestContext(t *testing.T) {
	const secret = "testing123"
	ctxs := make(chan context.Context, 1)
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		ctxs <- ctx
		return request.ReplyAccept()
	}))
	addr, _ := startTestServer(t, srv)

	client := NewRadClient(addr, secret)
	client.SetTimeout(serverStopTimeout)
	if _, err := client.Send(client.NewAccessRequest()); err != nil {
		t.Fatalf("send: %v", err)
	}
	ctx := <-ctxs
	select {
	case <-ctx.Done():
	case <-time.After(serverStopTimeout):
		t.Fatal("request context not cancelled after the handler returned")
	}
}

// Stop must cancel the context of in-flight requests.
func TestServerStopCancelsRequestContext(t *testing.T) {
	started := make(chan struct{})
	srv := NewServer("127.0.0.1:0", "secret", HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		close(started)
		<-ctx.Done()
		return nil
	}))
	addr, _ := startTestServer(t, srv)

	sendRaw(t, addr, rawAccessRequest(1))
	<-started
	stopped := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(serverStopTimeout):
		t.Fatal("Stop did not cancel the in-flight request context")
	}
}
