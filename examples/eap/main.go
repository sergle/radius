// EAP-MSCHAPv2 over 802.1X and RADIUS (RFC 3579), all three parties in one process:
//
//	Supplicant <──EAPOL (chan, emulated L2)──> NAS <──RADIUS (UDP)──> RADIUS server
//	main goroutine                             goroutine             goroutine
//
// The NAS (AP/switch) doesn't understand the EAP method: it starts the
// conversation with EAP-Request/Identity, relays EAP packets between EAPOL
// frames and EAP-Message attributes, echoes State, and opens the port on
// Access-Accept.
//
// Flow:
//
//	Supplicant → NAS   EAPOL-Start
//	NAS → Supplicant   EAP-Request/Identity
//	Supplicant → NAS   EAP-Response/Identity
//	NAS → Server       Access-Request   EAP-Response/Identity
//	Server → NAS       Access-Challenge EAP-Request/MSCHAPv2-Challenge + State
//	NAS → Supplicant   EAP-Request/MSCHAPv2-Challenge
//	Supplicant → NAS   EAP-Response/MSCHAPv2-Response
//	NAS → Server       Access-Request   EAP-Response/MSCHAPv2-Response + State
//	Server → NAS       Access-Challenge EAP-Request/MSCHAPv2-Success (S=) + State
//	                   (or Access-Reject + EAP-Failure)
//	NAS → Supplicant   EAP-Request/MSCHAPv2-Success
//	Supplicant → NAS   EAP-Response/MSCHAPv2-Success  (S= checked: the server knows the password too)
//	NAS → Server       Access-Request   EAP-Response/MSCHAPv2-Success + State
//	Server → NAS       Access-Accept    EAP-Success
//	NAS → Supplicant   EAP-Success, port authorized
//	Supplicant → NAS   EAPOL-Logoff
//
// Simplified: the MSCHAPv2 Failure round, the MPPE keys (MS-MPPE-Send-Key and
// MS-MPPE-Recv-Key in the Access-Accept, from MSCHAPv2MPPEKeys; they need
// FreeRADIUS dictionary.microsoft, see README) and the EAPOL-Key 4-way
// handshake are omitted.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/sergle/radius/v2"
)

// secret is random per run: the server and the NAS share this process.
// A real one comes from configuration, never from the source.
var secret = fmt.Sprintf("%x", randBytes(16))

const (
	serverName = "example-server"

	sessionTTL  = 30 * time.Second // a conversation must finish within this
	maxSessions = 1000             // Access-Reject beyond this many open conversations

	challengeLen    = 16 // MSCHAPv2 Authenticator/Peer-Challenge
	ntResponseLen   = 24
	reservedLen     = 8
	challengeValLen = challengeLen                                   // Value-Size in Challenge
	responseValLen  = challengeLen + reservedLen + ntResponseLen + 1 // Value-Size in Response (49): +Flags
)

// users is the server's credential store.
var users = map[string]string{"alice": "wonderland"}

func main() {
	srv := radius.NewServer("127.0.0.1:0", secret, newEAPServer())
	if err := srv.Listen(); err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := srv.Serve(); err != nil && !errors.Is(err, radius.ErrServerStopped) {
			log.Fatal(err)
		}
	}()
	defer srv.Stop()

	for _, c := range []struct{ user, pass string }{
		{"alice", "wonderland"},
		{"alice", "wrong"},
	} {
		port := newLink()
		done := make(chan struct{})
		go func() {
			nas(port, srv.Addr().String())
			close(done)
		}()
		ok := supplicant(port, c.user, c.pass)
		<-done
		log.Printf("result: %s/%s → authenticated=%v\n\n", c.user, c.pass, ok)
	}
}

// ── EAPOL (IEEE 802.1X), emulated L2 link ────────────────────────────────────

type eapolType uint8

const (
	eapolPacket eapolType = 0 // body is an EAP packet
	eapolStart  eapolType = 1
	eapolLogoff eapolType = 2
)

func (t eapolType) String() string {
	switch t {
	case eapolPacket:
		return "EAP-Packet"
	case eapolStart:
		return "EAPOL-Start"
	case eapolLogoff:
		return "EAPOL-Logoff"
	}
	return fmt.Sprintf("EAPOL-%d", uint8(t))
}

// eapol is an EAPOL frame (EtherType 0x888E) with its body as wire bytes.
type eapol struct {
	Type eapolType
	Body []byte
}

// link is a point-to-point L2 link between a supplicant and a NAS port.
type link struct {
	toNAS        chan eapol
	toSupplicant chan eapol
}

func newLink() link {
	return link{toNAS: make(chan eapol), toSupplicant: make(chan eapol)}
}

// eapFrame wraps an EAP packet in an EAPOL frame.
func eapFrame(eap *radius.EapPacket) eapol {
	return eapol{Type: eapolPacket, Body: eap.Encode()}
}

// ── NAS (authenticator) ──────────────────────────────────────────────────────

// nas serves one port: relays EAP between EAPOL and RADIUS until EAPOL-Logoff.
func nas(port link, server string) {
	client := radius.NewRadClient(server, secret)
	client.SetTimeout(2 * time.Second)

	var user string  // from EAP-Response/Identity
	var state []byte // RADIUS State echoed in each round
	for f := range port.toNAS {
		switch f.Type {
		case eapolStart:
			log.Printf("nas: ← %s → EAP-Request/Identity", f.Type)
			port.toSupplicant <- eapFrame(&radius.EapPacket{Code: radius.EapCodeRequest, Identifier: 1, Type: radius.EapTypeIdentity})
		case eapolLogoff:
			log.Printf("nas: ← %s, port unauthorized", f.Type)
			close(port.toSupplicant)
			return
		case eapolPacket:
			eap, err := radius.EapDecode(f.Body)
			if err != nil {
				log.Printf("nas: bad EAP frame: %v", err)
				continue
			}
			if eap.Type == radius.EapTypeIdentity {
				user = string(eap.Data)
			}
			req := client.NewAccessRequest()
			req.AddAVP(radius.AVP{Type: radius.AttrUserName, Value: []byte(user)})
			req.SetEAPMessage(eap)
			if state != nil {
				req.AddAVP(radius.AVP{Type: radius.AttrState, Value: state})
			}
			reply, err := client.Send(req)
			if err != nil {
				log.Printf("nas: RADIUS error: %v", err)
				continue
			}
			state = nil
			if s := reply.GetAVP(radius.AttrState); s != nil {
				state = append([]byte(nil), s.Value...)
			}
			switch reply.Code {
			case radius.AccessAccept:
				log.Printf("nas: ← %s, port authorized for %q", reply.Code, user)
			case radius.AccessReject:
				log.Printf("nas: ← %s, port stays unauthorized", reply.Code)
			default:
				log.Printf("nas: ← %s, relaying", reply.Code)
			}
			if out := reply.GetEAPMessage(); out != nil {
				port.toSupplicant <- eapFrame(out)
			}
		}
	}
}

// ── Server ───────────────────────────────────────────────────────────────────

type session struct {
	user      string
	challenge []byte
	expires   time.Time
	verified  bool // NT-Response checked and Success sent; waiting for the peer's ack
}

// eapServer keeps per-conversation state keyed by the State attribute.
type eapServer struct {
	mu       sync.Mutex
	sessions map[string]session
}

func newEAPServer() *eapServer {
	return &eapServer{sessions: map[string]session{}}
}

// put stores sess under a new State; false if too many conversations are open.
// Expired sessions are dropped first, so abandoned ones don't pile up.
func (s *eapServer) put(sess session) (state string, ok bool) {
	now := time.Now()
	sess.expires = now.Add(sessionTTL)
	state = fmt.Sprintf("%x", randBytes(16))
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= maxSessions {
		return "", false
	}
	s.sessions[state] = sess
	return state, true
}

// take removes and returns the session of req's State, if it hasn't expired.
func (s *eapServer) take(req *radius.Packet) (session, bool) {
	state := req.GetAVP(radius.AttrState)
	if state == nil {
		return session{}, false
	}
	s.mu.Lock()
	sess, ok := s.sessions[string(state.Value)]
	delete(s.sessions, string(state.Value))
	s.mu.Unlock()
	return sess, ok && time.Now().Before(sess.expires)
}

func (s *eapServer) RadiusHandle(ctx context.Context, req *radius.Packet) *radius.Packet {
	eap := req.GetEAPMessage()
	if eap == nil || eap.Code != radius.EapCodeResponse {
		return req.ReplyReject()
	}
	switch eap.Type {
	case radius.EapTypeIdentity:
		return s.challenge(req, eap)
	case radius.EapTypeMSCHAPV2:
		sess, ok := s.take(req)
		if !ok {
			return reject(req, eap)
		}
		if sess.verified {
			return s.finish(req, eap, sess)
		}
		return s.verify(req, eap, sess)
	}
	return req.ReplyReject()
}

// challenge answers EAP-Response/Identity with an MSCHAPv2 challenge.
func (s *eapServer) challenge(req *radius.Packet, eap *radius.EapPacket) *radius.Packet {
	user := string(eap.Data)
	ch := randBytes(challengeLen)
	state, ok := s.put(session{user: user, challenge: ch})
	if !ok {
		return reject(req, eap)
	}
	log.Printf("radius: identity %q → MSCHAPv2 challenge", user)

	// Challenge data: Value-Size, Challenge, Name
	data := append([]byte{challengeValLen}, ch...)
	data = append(data, serverName...)
	ms := &radius.MsChapV2Packet{
		Eap:    &radius.EapPacket{Code: radius.EapCodeRequest, Identifier: eap.Identifier + 1, Type: radius.EapTypeMSCHAPV2},
		OpCode: radius.MsChapV2OpCodeChallenge,
		Data:   data,
	}
	reply := req.ReplyChallenge()
	reply.SetEAPMessage(ms.ToEap())
	reply.AddAVP(radius.AVP{Type: radius.AttrState, Value: []byte(state)})
	return reply
}

// verify checks the NT-Response against the stored challenge and password and
// answers with the authenticator response (S=), which proves the server knows
// the password too.
func (s *eapServer) verify(req *radius.Packet, eap *radius.EapPacket, sess session) *radius.Packet {
	ms, err := radius.MsChapV2PacketFromEap(eap)
	if err != nil || ms.OpCode != radius.MsChapV2OpCodeResponse || len(ms.Data) < 1+responseValLen {
		return reject(req, eap)
	}
	// Response data: Value-Size, Peer-Challenge, Reserved, NT-Response, Flags, Name
	peer := ms.Data[1 : 1+challengeLen]
	got := ms.Data[1+challengeLen+reservedLen : 1+challengeLen+reservedLen+ntResponseLen]

	pass, known := users[sess.user]
	want, err := radius.MSCHAPv2NTResponse(sess.challenge, peer, sess.user, pass)
	if !known || err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		log.Printf("radius: %q bad NT-Response → Access-Reject", sess.user)
		return reject(req, eap)
	}
	auth := radius.MSCHAPv2AuthenticatorResponse(sess.challenge, peer, got, sess.user, pass)
	sess.verified = true
	state, ok := s.put(sess)
	if !ok {
		return reject(req, eap)
	}
	log.Printf("radius: %q NT-Response OK → MSCHAPv2 Success", sess.user)

	success := &radius.MsChapV2Packet{
		Eap:    &radius.EapPacket{Code: radius.EapCodeRequest, Identifier: eap.Identifier + 1, Type: radius.EapTypeMSCHAPV2},
		OpCode: radius.MsChapV2OpCodeSuccess,
		Data:   []byte(auth + " M=Welcome"),
	}
	reply := req.ReplyChallenge()
	reply.SetEAPMessage(success.ToEap())
	reply.AddAVP(radius.AVP{Type: radius.AttrState, Value: []byte(state)})
	return reply
}

// finish accepts the peer once it has acknowledged the Success (and so checked S=).
func (s *eapServer) finish(req *radius.Packet, eap *radius.EapPacket, sess session) *radius.Packet {
	if len(eap.Data) < 1 || radius.MsChapV2OpCode(eap.Data[0]) != radius.MsChapV2OpCodeSuccess {
		return reject(req, eap)
	}
	log.Printf("radius: %q acknowledged Success → Access-Accept", sess.user)
	reply := req.ReplyAccept()
	reply.SetEAPMessage(&radius.EapPacket{Code: radius.EapCodeSuccess, Identifier: eap.Identifier})
	return reply
}

// reject answers with Access-Reject and EAP-Failure.
func reject(req *radius.Packet, eap *radius.EapPacket) *radius.Packet {
	reply := req.ReplyReject()
	reply.SetEAPMessage(&radius.EapPacket{Code: radius.EapCodeFailure, Identifier: eap.Identifier})
	return reply
}

// ── Supplicant (end-user device) ─────────────────────────────────────────────

// supplicant authenticates over port and reports whether it got EAP-Success.
func supplicant(port link, user, pass string) bool {
	send := func(f eapol, what string) {
		log.Printf("supplicant: → %s%s", f.Type, what)
		port.toNAS <- f
	}
	defer func() {
		send(eapol{Type: eapolLogoff}, "")
		close(port.toNAS)
		for range port.toSupplicant { // drain until the NAS closes the link
		}
	}()

	var wantAuth string // S= the server must send, from our response
	send(eapol{Type: eapolStart}, "")
	for f := range port.toSupplicant {
		in, err := radius.EapDecode(f.Body)
		if err != nil {
			log.Printf("supplicant: bad EAP frame: %v", err)
			return false
		}
		log.Printf("supplicant: ← %s", in)
		switch {
		case in.Code == radius.EapCodeSuccess:
			return true
		case in.Code == radius.EapCodeFailure:
			return false
		case in.Type == radius.EapTypeIdentity:
			send(eapFrame(&radius.EapPacket{Code: radius.EapCodeResponse, Identifier: in.Identifier, Type: radius.EapTypeIdentity, Data: []byte(user)}), " Identity")
		case in.Type == radius.EapTypeMSCHAPV2 && wantAuth == "":
			out, auth, err := mschapResponse(in, user, pass)
			if err != nil {
				log.Printf("supplicant: %v", err)
				return false
			}
			wantAuth = auth
			send(eapFrame(out), " MSCHAPv2-Response")
		case in.Type == radius.EapTypeMSCHAPV2:
			ms, err := radius.MsChapV2PacketFromEap(in)
			if err != nil || ms.OpCode != radius.MsChapV2OpCodeSuccess || !strings.HasPrefix(string(ms.Data), wantAuth) {
				log.Printf("supplicant: bad authenticator response, the server doesn't know the password")
				return false
			}
			ack := &radius.EapPacket{Code: radius.EapCodeResponse, Identifier: in.Identifier, Type: radius.EapTypeMSCHAPV2,
				Data: []byte{byte(radius.MsChapV2OpCodeSuccess)}}
			send(eapFrame(ack), " MSCHAPv2-Success")
		default:
			log.Printf("supplicant: unsupported EAP type %s", in.Type)
			return false
		}
	}
	return false
}

// mschapResponse answers an EAP-Request/MSCHAPv2-Challenge (RFC 2759) and
// returns the authenticator response (S=) the server must send back.
func mschapResponse(in *radius.EapPacket, user, pass string) (*radius.EapPacket, string, error) {
	ms, err := radius.MsChapV2PacketFromEap(in)
	if err != nil || ms.OpCode != radius.MsChapV2OpCodeChallenge || len(ms.Data) < 1+challengeLen {
		return nil, "", errors.New("bad MSCHAPv2 challenge")
	}
	authChallenge := ms.Data[1 : 1+challengeLen]
	peer := randBytes(challengeLen)
	nt, err := radius.MSCHAPv2NTResponse(authChallenge, peer, user, pass)
	if err != nil {
		return nil, "", err
	}

	// Value-Size, Peer-Challenge, Reserved (zero), NT-Response, Flags (zero), Name
	data := append([]byte{responseValLen}, peer...)
	data = append(data, make([]byte, reservedLen)...)
	data = append(data, nt...)
	data = append(data, 0)
	data = append(data, user...)
	resp := &radius.MsChapV2Packet{
		Eap:    &radius.EapPacket{Code: radius.EapCodeResponse, Identifier: in.Identifier, Type: radius.EapTypeMSCHAPV2},
		OpCode: radius.MsChapV2OpCodeResponse,
		Data:   data,
	}
	return resp.ToEap(), radius.MSCHAPv2AuthenticatorResponse(authChallenge, peer, nt, user, pass), nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
