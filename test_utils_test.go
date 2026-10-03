package radius

import "testing"

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
