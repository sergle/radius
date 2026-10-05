package radius

import (
	"context"
	"errors"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// DefaultMaxConcurrent is the default limit of concurrently running handlers.
const DefaultMaxConcurrent = 1024

// Service handles inbound RADIUS requests and returns a reply packet.
// The server sets the reply's Identifier, Secret and Authenticator from the request.
// Encrypted attributes (e.g. Tunnel-Password) need them when added, so use request.Reply().
type Service interface {
	RadiusHandle(ctx context.Context, request *Packet) *Packet
}

// HandlerFunc adapts a function to the Service interface.
type HandlerFunc func(ctx context.Context, request *Packet) *Packet

// RadiusHandle calls f(ctx, request).
func (f HandlerFunc) RadiusHandle(ctx context.Context, request *Packet) *Packet {
	return f(ctx, request)
}

type radiusService struct {
}

func (p *radiusService) RadiusHandle(ctx context.Context, request *Packet) *Packet {
	npac := request.Reply()
	npac.Code = AccessAccept
	// 18 is Reply-Message
	npac.AddAVP(AVP{Type: 18, Value: avpString.FromString("Welcome")})
	return npac
}

// NewServer constructs a UDP RADIUS server bound to addr with the given shared secret.
func NewServer(addr string, secret string, service Service) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		addr:          addr,
		secret:        secret,
		service:       service,
		maxConcurrent: DefaultMaxConcurrent,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// NewServerWithClientList constructs a UDP RADIUS server bound to addr that
// resolves shared secrets per client using clients.
//
// If a request comes from a host not present in the list, it is dropped.
func NewServerWithClientList(addr string, clients *ClientList, service Service) *Server {
	s := NewServer(addr, "", service)
	s.clients.Store(clients)
	return s
}

// Server is a simple UDP RADIUS server.
type Server struct {
	addr    string
	secret  string
	clients atomic.Pointer[ClientList] // nil: use secret
	service Service

	requireMA        bool // drop Access-Requests without Message-Authenticator
	allowProxyNoAuth bool // accept Access-Requests with Proxy-State but no Message-Authenticator
	maxConcurrent    int  // max in-flight handlers, <= 0 means unlimited

	mu       sync.Mutex // guards conn, serving, maxConcurrent and handlers.Add against Stop
	conn     *net.UDPConn
	serving  bool
	ctx      context.Context
	cancel   context.CancelFunc
	handlers sync.WaitGroup // in-flight handlers
}

var (
	// ErrServerStopped is returned by Listen, Serve and ListenAndServe after Stop.
	ErrServerStopped    = errors.New("radius: server stopped")
	errAlreadyListening = errors.New("radius: server already listening")
	errNotListening     = errors.New("radius: Serve called before Listen")
	errServerRunning    = errors.New("radius: server already serving")
)

var serverBufferPool = newPool(func() []byte {
	return make([]byte, maxPacketLen)
})

// Listen binds the UDP socket; after it returns, Addr reports the bound address.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return ErrServerStopped
	}
	if s.conn != nil {
		return errAlreadyListening
	}
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Addr returns the bound address, or nil if the server is not listening.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// ListenAndServe listens on UDP and processes RADIUS requests until stopped.
// After Stop it returns ErrServerStopped.
//
// Each request is handled in its own goroutine (at most SetMaxConcurrent at
// a time); the server reuses internal buffers to reduce allocations.
func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Serve processes RADIUS requests on the socket bound by Listen until stopped.
// After Stop it returns ErrServerStopped.
func (s *Server) Serve() error {
	s.mu.Lock()
	conn, ctx, maxConcurrent := s.conn, s.ctx, s.maxConcurrent
	if ctx.Err() == nil && conn != nil {
		s.serving = true
	}
	s.mu.Unlock()
	if ctx.Err() != nil {
		return ErrServerStopped
	}
	if conn == nil {
		return errNotListening
	}
	defer conn.Close()

	var sem chan struct{}
	if maxConcurrent > 0 {
		sem = make(chan struct{}, maxConcurrent)
	}

	for {
		b := serverBufferPool.Get()
		// Ensure full buffer length for reads, even if a shorter slice was pooled.
		b = b[:cap(b)]
		n, raddr, err := conn.ReadFromUDP(b)
		if err != nil {
			serverBufferPool.Put(b)
			if ctx.Err() != nil {
				return ErrServerStopped
			}
			return err
		}

		// Wait for a free slot; excess datagrams queue in the socket buffer.
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				serverBufferPool.Put(b)
				return ErrServerStopped
			}
		}
		// Register the handler under mu so Stop can't start waiting before Add.
		s.mu.Lock()
		stopped := ctx.Err() != nil
		if !stopped {
			s.handlers.Add(1)
		}
		s.mu.Unlock()
		if stopped {
			serverBufferPool.Put(b)
			return ErrServerStopped
		}

		go func(buf []byte, n int, addr *net.UDPAddr) {
			defer s.handlers.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			defer serverBufferPool.Put(buf)
			// Runs after p.Release and before buf is returned to the pool.
			defer func() {
				if r := recover(); r != nil {
					logger().Error("radius: panic handling packet", "client", addr, "panic", r, "stack", string(debug.Stack()))
				}
			}()
			secret, ok := s.secretForAddr(addr)
			if !ok {
				logger().Warn("radius: unknown client", "client", addr)
				return
			}

			opts := DecodeOptions{RequireMessageAuthenticator: s.requireMA}
			p, err := DecodeRequestPooledWithOptions(secret, buf[:n], &opts)
			if err != nil {
				logger().Warn("radius: decode packet", "client", addr, "error", err)
				return
			}
			defer p.Release()
			if p.Code == AccessRequest && !s.allowProxyNoAuth &&
				p.HasAVP(AttrProxyState) && !p.HasAVP(AttrMessageAuthenticator) {
				logger().Warn("radius: dropping Access-Request with Proxy-State but no Message-Authenticator", "client", addr)
				return
			}
			p.ClientAddr = addr.String()

			reqCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			npac := s.service.RadiusHandle(reqCtx, p)
			if npac == nil {
				return
			}
			npac.Identifier = p.Identifier
			npac.Secret = secret
			// the response authenticator is computed over the request authenticator
			npac.Authenticator = p.Authenticator

			// Reply AVPs may alias buf (values copied from the request),
			// so encode into a separate buffer.
			out := serverBufferPool.Get()
			out = out[:cap(out)]
			defer serverBufferPool.Put(out)
			writtenN, err := npac.EncodeTo(out)
			if err != nil {
				logger().Error("radius: encode reply", "client", addr, "error", err)
				return
			}
			conn.WriteToUDP(out[:writtenN], addr)
		}(b, n, raddr)
	}
}

// SetMaxConcurrent limits concurrently running handlers (default
// DefaultMaxConcurrent, <= 0 means unlimited). It fails once Serve has started.
func (s *Server) SetMaxConcurrent(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serving {
		return errServerRunning
	}
	s.maxConcurrent = n
	return nil
}

// SetClientList sets the client list used to resolve per-client shared secrets.
// When set, the server will prefer the list over the Server.secret field.
// It is safe to call while the server is serving; nil reverts to the shared secret.
func (s *Server) SetClientList(clients *ClientList) {
	s.clients.Store(clients)
}

// SetRequireMessageAuthenticator makes the server drop Access-Requests without a
// Message-Authenticator (default false). Call it before Listen/Serve.
func (s *Server) SetRequireMessageAuthenticator(require bool) {
	s.requireMA = require
}

// SetLimitProxyState controls dropping Access-Requests that carry Proxy-State but
// no Message-Authenticator (default true, Blast-RADIUS mitigation). Call it before Listen/Serve.
func (s *Server) SetLimitProxyState(limit bool) {
	s.allowProxyNoAuth = !limit
}

func (s *Server) secretForAddr(addr *net.UDPAddr) (string, bool) {
	if clients := s.clients.Load(); clients != nil {
		host := addr.IP.String()
		if host == "" {
			// Defensive: addr.IP should always be set, but fall back to parsing.
			if h, _, err := net.SplitHostPort(addr.String()); err == nil {
				host = h
			}
		}
		cl := clients.Get(host)
		if cl == nil {
			// Also allow indexing by the full remote address (host:port).
			// This is useful when multiple clients share an IP but differ by port
			// (for example, during local testing).
			cl = clients.Get(addr.String())
		}
		if cl == nil {
			return "", false
		}
		sec := cl.GetSecret()
		if sec == "" {
			return "", false
		}
		return sec, true
	}

	if s.secret == "" {
		return "", false
	}
	return s.secret, true
}

// Stop cancels the server context, closes the UDP listener and waits for
// in-flight handlers to return. It is safe to call before Listen and more
// than once, but must not be called from a handler.
func (s *Server) Stop() {
	s.mu.Lock()
	s.cancel()
	if s.conn != nil {
		s.conn.Close()
	}
	s.mu.Unlock()
	s.handlers.Wait()
}
