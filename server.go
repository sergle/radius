package radius

import (
	"context"
	"errors"
	"log"
	"net"
	"runtime/debug"
	"sync"
)

// Service handles inbound RADIUS requests and returns a reply packet.
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
	s := &Server{
		addr:    addr,
		secret:  secret,
		clients: nil,
		service: service,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// NewServerWithClientList constructs a UDP RADIUS server bound to addr that
// resolves shared secrets per client using clients.
//
// If a request comes from a host not present in the list, it is dropped.
func NewServerWithClientList(addr string, clients *ClientList, service Service) *Server {
	s := &Server{
		addr:    addr,
		clients: clients,
		service: service,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// Server is a simple UDP RADIUS server.
type Server struct {
	addr    string
	secret  string
	clients *ClientList
	service Service

	mu     sync.Mutex // guards conn
	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	ErrServerStopped    = errors.New("radius: server stopped")
	errAlreadyListening = errors.New("radius: server already listening")
	errNotListening     = errors.New("radius: Serve called before Listen")
)

var serverBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxPacketLen)
	},
}

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
//
// Each request is handled in its own goroutine; the server reuses internal
// buffers to reduce allocations.
func (s *Server) ListenAndServe() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Serve processes RADIUS requests on the socket bound by Listen until stopped.
func (s *Server) Serve() error {
	s.mu.Lock()
	conn, ctx := s.conn, s.ctx
	s.mu.Unlock()
	if conn == nil {
		return errNotListening
	}
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		b := serverBufferPool.Get().([]byte)
		// Ensure full buffer length for reads, even if a shorter slice was pooled.
		b = b[:cap(b)]
		n, raddr, err := conn.ReadFromUDP(b)
		if err != nil {
			serverBufferPool.Put(b)
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		go func(ctx context.Context, buf []byte, n int, addr *net.UDPAddr) {
			defer serverBufferPool.Put(buf)
			// Runs after p.Release and before buf is returned to the pool.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("panic handling packet from %s: %v\n%s", addr, r, debug.Stack())
				}
			}()
			secret, ok := s.secretForAddr(addr)
			if !ok {
				log.Printf("unknown RADIUS client %s", addr.String())
				return
			}

			p, err := DecodeRequestPooled(secret, buf[:n])
			if err != nil {
				log.Printf("decode packet error %v", err)
				return
			}
			defer p.Release()
			p.ClientAddr = addr.String()

			npac := s.service.RadiusHandle(ctx, p)
			if npac == nil {
				return
			}
			npac.Identifier = p.Identifier
			npac.Secret = secret

			// Reply AVPs may alias buf (values copied from the request),
			// so encode into a separate buffer.
			out := serverBufferPool.Get().([]byte)
			out = out[:cap(out)]
			defer serverBufferPool.Put(out)
			writtenN, err := npac.EncodeTo(out)
			if err != nil {
				log.Printf("encode packet error %v", err)
				return
			}
			conn.WriteToUDP(out[:writtenN], addr)
		}(ctx, b, n, raddr)
	}
}

// SetClientList sets the client list used to resolve per-client shared secrets.
// When set, the server will prefer the list over the Server.secret field.
func (s *Server) SetClientList(clients *ClientList) {
	s.clients = clients
}

func (s *Server) secretForAddr(addr *net.UDPAddr) (string, bool) {
	if s.clients != nil {
		host := addr.IP.String()
		if host == "" {
			// Defensive: addr.IP should always be set, but fall back to parsing.
			if h, _, err := net.SplitHostPort(addr.String()); err == nil {
				host = h
			}
		}
		cl := s.clients.Get(host)
		if cl == nil {
			// Also allow indexing by the full remote address (host:port).
			// This is useful when multiple clients share an IP but differ by port
			// (for example, during local testing).
			cl = s.clients.Get(addr.String())
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

// Stop cancels the server context and closes the UDP listener.
// It is safe to call before Listen and more than once.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancel()
	if s.conn != nil {
		s.conn.Close()
	}
}
