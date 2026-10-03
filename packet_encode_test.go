package radius

import (
	"bytes"
	"context"
	"crypto/md5"
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
			// a request keeps its wire authenticator, as Reply() and reply checks need it
			if !bytes.Equal(req.Authenticator[:], reqBuf[4:packetHeaderLen]) {
				t.Fatalf("request Authenticator %x, encoded %x", req.Authenticator, reqBuf[4:packetHeaderLen])
			}
			reqAuth := req.Authenticator[:]

			reply := tc.reply(req)
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
	if !bytes.Equal(req.Authenticator[:], b1[4:packetHeaderLen]) {
		t.Errorf("request Authenticator %x, encoded %x", req.Authenticator, b1[4:packetHeaderLen])
	}
	before.Authenticator = req.Authenticator
	if !samePacket(req, before) {
		t.Errorf("Encode changed the AVPs: %v", req.AVPs)
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

// An Access-Request without an authenticator gets a random one stored in the packet.
func TestEncodeAccessRequestGeneratesAuthenticator(t *testing.T) {
	const secret = "testing123"

	req := &Packet{Code: AccessRequest, Secret: secret}
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if req.Authenticator == [authenticatorLen]byte{} {
		t.Fatal("Authenticator not generated")
	}
	if !bytes.Equal(b[4:packetHeaderLen], req.Authenticator[:]) {
		t.Errorf("encoded authenticator %x, packet has %x", b[4:packetHeaderLen], req.Authenticator)
	}
	if len(req.AVPs) != 0 {
		t.Errorf("Encode added AVPs to the packet: %v", req.AVPs)
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
