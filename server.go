package radius

import (
	"log"
	"net"
)

type Service interface {
	RadiusHandle(request *Packet) *Packet
}

type HandlerFunc func(request *Packet) *Packet

func (f HandlerFunc) RadiusHandle(request *Packet) *Packet {
	return f(request)
}

type radiusService struct {
}

func (p *radiusService) RadiusHandle(request *Packet) *Packet {
	npac := request.Reply()
	npac.Code = AccessAccept
	// 18 is Reply-Message
	npac.AddAVP(AVP{Type: 18, Value: avpString.FromString("Welcome")})
	return npac
}

func NewServer(addr string, secret string, service Service) *Server {
	s := &Server{
		addr:    addr,
		secret:  secret,
		service: service,
	}
	return s
}

type Server struct {
	addr    string
	secret  string
	service Service
	conn    *net.UDPConn
}

func (s *Server) ListenAndServe() error {
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
		b := make([]byte, 4096)
		n, raddr, err := s.conn.ReadFromUDP(b)
		if err != nil {
			return err
		}

		go func(buf []byte, addr *net.UDPAddr) {
			p, err := DecodeRequest(s.secret, buf)
			if err != nil {
				log.Printf("decode packet error %v", err)
				return
			}
			p.ClientAddr = addr.String()
			npac := s.service.RadiusHandle(p)
			if npac == nil {
				return
			}
			npac.Identifier = p.Identifier
			npac.Secret = s.secret
			buf, err = npac.Encode()
			if err != nil {
				log.Printf("encode packet error %v", err)
				return
			}
			s.conn.WriteToUDP(buf, addr)
		}(b[:n], raddr)
	}
}

func (s *Server) Stop() {
	if s.conn != nil {
		s.conn.Close()
	}
}
