package radius

import (
	"context"
	"log"
	"net"
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
		service: service,
	}
	return s
}

// Server is a simple UDP RADIUS server.
type Server struct {
	addr    string
	secret  string
	service Service
	conn    *net.UDPConn
	ctx     context.Context
	cancel  context.CancelFunc
}

var serverBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// ListenAndServe listens on UDP and processes RADIUS requests until stopped.
//
// Each request is handled in its own goroutine; the server reuses internal
// buffers to reduce allocations.
func (s *Server) ListenAndServe() error {
	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
	}
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer s.conn.Close()

	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
		}

		b := serverBufferPool.Get().([]byte)
		n, raddr, err := s.conn.ReadFromUDP(b)
		if err != nil {
			serverBufferPool.Put(b)
			select {
			case <-s.ctx.Done():
				return nil
			default:
				return err
			}
		}

		go func(ctx context.Context, buf []byte, addr *net.UDPAddr) {
			defer serverBufferPool.Put(buf)
			p, err := DecodeRequestPooled(s.secret, buf)
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
			npac.Secret = s.secret

			// Reuse the same buffer for encoding if possible
			// RADIUS max length is 4096, so buf is enough
			n, err := npac.EncodeTo(buf)
			if err != nil {
				log.Printf("encode packet error %v", err)
				return
			}
			s.conn.WriteToUDP(buf[:n], addr)
		}(s.ctx, b[:n], raddr)
	}
}

// Stop cancels the server context and closes the UDP listener.
func (s *Server) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		s.conn.Close()
	}
}
