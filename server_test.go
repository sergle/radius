package radius

import (
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
