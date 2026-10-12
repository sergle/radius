package radius

import (
	"bytes"
	"context"
	"crypto/md5"
	"sync"
	"testing"
)

// samePacket compares the fields Encode could change.
func samePacket(a, b *Packet) bool {
	if a.Authenticator != b.Authenticator || len(a.AVPs) != len(b.AVPs) {
		return false
	}
	for i := range a.AVPs {
		if a.AVPs[i].Type != b.AVPs[i].Type || !bytes.Equal(a.AVPs[i].Value, b.AVPs[i].Value) {
			return false
		}
	}
	return true
}

// Encoding a reply twice must give identical, verifiable output and leave the packet unchanged.
func TestEncodeReplyTwice(t *testing.T) {
	const secret = "testing123"

	for _, tc := range []struct {
		name    string
		reqCode PacketCode
		reply   func(*Packet) *Packet
	}{
		{"Access-Accept", AccessRequest, (*Packet).ReplyAccept},
		{"Accounting-Response", AccountingRequest, (*Packet).ReplyAccountingResponse},
		{"CoA-ACK", CoARequest, (*Packet).ReplyCoAAccept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := Request(tc.reqCode, secret)
			reqBuf, err := req.Encode()
			if err != nil {
				t.Fatalf("Encode request: %v", err)
			}
			// the server replies to the request as sent
			sent, err := DecodeRequest(secret, reqBuf)
			if err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}
			reqAuth := reqBuf[4:packetHeaderLen]

			reply := tc.reply(sent)
			reply.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("hello")})
			before := reply.Copy()

			b1, err := reply.Encode()
			if err != nil {
				t.Fatalf("first Encode: %v", err)
			}
			if !samePacket(reply, before) {
				t.Errorf("Encode changed the packet:\nbefore %+v\nafter  %+v", before, reply)
			}
			b2, err := reply.Encode()
			if err != nil {
				t.Fatalf("second Encode: %v", err)
			}
			if !bytes.Equal(b1, b2) {
				t.Errorf("encodings differ:\nfirst  %x\nsecond %x", b1, b2)
			}
			for i, b := range [][]byte{b1, b2} {
				if _, err := DecodeReply(secret, b, reqAuth); err != nil {
					t.Errorf("DecodeReply of encoding %d: %v", i+1, err)
				}
			}
		})
	}
}

// Re-sending an Accounting-Request must produce a valid packet each time.
func TestEncodeAccountingRequestTwice(t *testing.T) {
	const secret = "testing123"

	req := Request(AccountingRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	before := req.Copy()

	b1, err := req.Encode()
	if err != nil {
		t.Fatalf("first Encode: %v", err)
	}
	if !samePacket(req, before) {
		t.Errorf("Encode changed the packet:\nbefore %+v\nafter  %+v", before, req)
	}

	b2, err := req.Encode()
	if err != nil {
		t.Fatalf("second Encode: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("encodings differ:\nfirst  %x\nsecond %x", b1, b2)
	}
	if !samePacket(req, before) {
		t.Errorf("second Encode changed the packet:\nbefore %+v\nafter  %+v", before, req)
	}
	for i, b := range [][]byte{b1, b2} {
		if _, err := DecodeRequest(secret, b); err != nil {
			t.Errorf("DecodeRequest of encoding %d: %v", i+1, err)
		}
	}
}

// An Access-Request without an authenticator is sent with a random one; the packet is unchanged.
func TestEncodeAccessRequestGeneratesAuthenticator(t *testing.T) {
	const secret = "testing123"

	req := &Packet{Code: AccessRequest, Secret: secret}
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if [authenticatorLen]byte(b[4:packetHeaderLen]) == zeroAuthenticator {
		t.Fatal("Authenticator not generated")
	}
	if req.Authenticator != zeroAuthenticator || len(req.AVPs) != 0 {
		t.Errorf("Encode changed the packet: %+v", req)
	}
	if _, err := DecodeRequestWithOptions(secret, b, &DecodeOptions{RequireMessageAuthenticator: true}); err != nil {
		t.Errorf("DecodeRequest: %v", err)
	}
}

// RadClient must verify replies to both Access and Accounting requests, also when re-sent.
func TestRadClientVerifiesReplies(t *testing.T) {
	const secret = "testing123"

	handler := HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		switch request.Code {
		case AccessRequest:
			return request.ReplyAccept()
		case AccountingRequest:
			return request.ReplyAccountingResponse()
		}
		return nil
	})

	addr, _ := startTestServer(t, NewServer("127.0.0.1:0", secret, handler))

	client := NewRadClient(addr, secret)
	for _, tc := range []struct {
		req  *Packet
		want PacketCode
	}{
		{client.NewAccessRequest(), AccessAccept},
		{client.NewAccountingRequest(), AccountingResponse},
	} {
		for i := 1; i <= 2; i++ {
			reply, err := client.Send(tc.req)
			if err != nil {
				t.Fatalf("%v send %d: %v", tc.req.Code, i, err)
			}
			if reply.Code != tc.want {
				t.Errorf("%v send %d: got %v, want %v", tc.req.Code, i, reply.Code, tc.want)
			}
		}
	}
}

// One request may be sent from several goroutines at once (go test -race).
func TestRadClientConcurrentSend(t *testing.T) {
	const (
		secret  = "testing123"
		senders = 4
	)

	handler := HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		if request.Code == AccessRequest {
			return request.ReplyAccept()
		}
		return request.ReplyAccountingResponse()
	})
	addr, _ := startTestServer(t, NewServer("127.0.0.1:0", secret, handler))

	client := NewRadClient(addr, secret)
	for _, req := range []*Packet{
		{Code: AccessRequest, Secret: secret}, // authenticator generated at Encode
		client.NewAccountingRequest(),
	} {
		before := req.Copy()
		var wg sync.WaitGroup
		errs := make(chan error, senders)
		for range senders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := client.Send(req); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("%v: %v", req.Code, err)
		}
		if !samePacket(req, before) {
			t.Errorf("%v: Send changed the packet:\nbefore %+v\nafter  %+v", req.Code, before, req)
		}
	}
}

// Re-encoding a decoded Access-Request must keep its AVPs and replace its Message-Authenticator.
func TestEncodeDecodedAccessRequest(t *testing.T) {
	const secret = "testing123"

	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	orig, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	for _, tc := range []struct {
		name   string
		decode func(string, []byte) (*Packet, error)
	}{
		{"normal", DecodeRequest},
		{"lazy", DecodeRequestLazy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.decode(secret, append([]byte(nil), orig...))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			p.Identifier++
			b, err := p.Encode()
			if err != nil {
				t.Fatalf("re-Encode: %v", err)
			}
			if len(b) != len(orig) {
				t.Errorf("re-encoded length %d, want %d", len(b), len(orig))
			}
			got, err := DecodeRequest(secret, b)
			if err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}
			if got.GetUsername() != "alice" {
				t.Errorf("User-Name = %q, want %q", got.GetUsername(), "alice")
			}
		})
	}
}

// An existing Message-Authenticator is filled in place, keeping its position.
func TestEncodeKeepsMessageAuthenticatorPosition(t *testing.T) {
	const secret = "testing123"

	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrMessageAuthenticator, Value: make([]byte, md5.Size)})
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	orig, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if orig[packetHeaderLen] != byte(AttrMessageAuthenticator) {
		t.Fatalf("Message-Authenticator not first in %x", orig)
	}

	for _, tc := range []struct {
		name   string
		decode func(string, []byte) (*Packet, error)
	}{
		{"normal", DecodeRequest},
		{"lazy", DecodeRequestLazy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.decode(secret, append([]byte(nil), orig...))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			p.Identifier++
			b, err := p.Encode()
			if err != nil {
				t.Fatalf("re-Encode: %v", err)
			}
			if len(b) != len(orig) || b[packetHeaderLen] != byte(AttrMessageAuthenticator) {
				t.Fatalf("re-encoded packet changed layout: %x", b)
			}
			if _, err := DecodeRequestWithOptions(secret, b, &DecodeOptions{RequireMessageAuthenticator: true}); err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}
		})
	}
}

func TestEncodeRejectsBadMessageAuthenticatorLength(t *testing.T) {
	p := Request(AccessRequest, "testing123")
	p.AddAVP(AVP{Type: AttrMessageAuthenticator, Value: []byte{1, 2, 3}})
	if _, err := p.Encode(); err == nil {
		t.Fatal("Encode accepted a 3-byte Message-Authenticator")
	}
}

// Blast-RADIUS: EncodeTo must put a new Message-Authenticator first in Access-* packets.
func TestEncodeMessageAuthenticatorFirst(t *testing.T) {
	const secret = "testing123"
	requireMA := &DecodeOptions{RequireMessageAuthenticator: true}

	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	reqBuf, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode request: %v", err)
	}

	for _, tc := range []struct {
		name string
		p    *Packet
	}{
		{"Access-Request", req},
		{"Access-Accept", req.ReplyAccept()},
		{"Access-Reject", req.ReplyReject()},
		{"Access-Challenge", req.ReplyChallenge()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := reqBuf
			if tc.p != req {
				tc.p.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("hello")})
				if b, err = tc.p.Encode(); err != nil {
					t.Fatalf("Encode: %v", err)
				}
			}
			if b[packetHeaderLen] != byte(AttrMessageAuthenticator) || b[packetHeaderLen+1] != messageAuthenticatorLen {
				t.Fatalf("Message-Authenticator not first in %x", b)
			}

			var got *Packet
			if tc.p == req {
				got, err = DecodeRequestWithOptions(secret, b, requireMA)
			} else {
				got, err = DecodeReplyWithOptions(secret, b, req.Authenticator[:], requireMA)
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n := len(got.AVPs); n != 2 {
				t.Errorf("got %d AVPs, want 2", n)
			}
		})
	}
}
