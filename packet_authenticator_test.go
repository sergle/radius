package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"testing"
)

// Ensure that non-Access request authenticators are computed using a zero
// vector in the hash input, even if the caller pre-populates Authenticator.
func TestNonAccessRequestAuthenticatorUsesZeroVector(t *testing.T) {
	const secret = "testing123"

	p := &Packet{
		Secret:     secret,
		Code:       AccountingRequest,
		Identifier: 1,
	}

	// Deliberately set a non-zero authenticator to simulate a buggy caller.
	for i := range p.Authenticator {
		p.Authenticator[i] = byte(i + 1)
	}

	// Encode and then decode using the library's own verifier. If the encoder
	// hashed with the non-zero authenticator instead of zeros, verification
	// will fail.
	b, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if _, err := DecodeRequest(secret, b); err != nil {
		t.Fatalf("DecodeRequest failed: %v", err)
	}
}

func TestRequireMessageAuthenticatorOption(t *testing.T) {
	const secret = "testing123"

	// Build a normal Access-Request, then remove the Message-Authenticator AVP
	// to simulate legacy / non-compliant clients.
	p := Request(AccessRequest, secret)
	p.Identifier = 1
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	b, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// EncodeTo adds Message-Authenticator as the first attribute of Access-* packets.
	if b[packetHeaderLen] != byte(AttrMessageAuthenticator) || b[packetHeaderLen+1] != messageAuthenticatorLen {
		t.Fatalf("expected leading Message-Authenticator AVP, got type=%d len=%d", b[packetHeaderLen], b[packetHeaderLen+1])
	}

	withoutMA := append(append([]byte(nil), b[:packetHeaderLen]...), b[packetHeaderLen+messageAuthenticatorLen:]...)
	binary.BigEndian.PutUint16(withoutMA[2:4], uint16(len(withoutMA)))

	// Default behavior: still decodes (compatibility).
	if _, err := DecodeRequest(secret, withoutMA); err != nil {
		t.Fatalf("DecodeRequest (default) should succeed without Message-Authenticator: %v", err)
	}

	// Opt-in behavior: reject missing Message-Authenticator for Access-* packets.
	_, err = DecodeRequestWithOptions(secret, withoutMA, &DecodeOptions{RequireMessageAuthenticator: true})
	if err != ErrMessageAuthenticatorMissing {
		t.Fatalf("DecodeRequestWithOptions expected %v, got %v", ErrMessageAuthenticatorMissing, err)
	}
}

// Lazy decoding must verify the Message-Authenticator that EncodeTo adds to
// every Access-* packet, for both requests and replies.
func TestLazyDecodeVerifiesMessageAuthenticator(t *testing.T) {
	const secret = "testing123"

	req := Request(AccessRequest, secret)
	req.Identifier = 7
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	reqBuf, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode request failed: %v", err)
	}

	lazyReq, err := DecodeRequestLazy(secret, reqBuf)
	if err != nil {
		t.Fatalf("DecodeRequestLazy failed: %v", err)
	}
	if got := lazyReq.GetUsername(); got != "alice" {
		t.Fatalf("lazy request User-Name = %q, want %q", got, "alice")
	}

	reply := req.Reply()
	reply.Code = AccessAccept
	reply.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("welcome")})
	replyBuf, err := reply.Encode()
	if err != nil {
		t.Fatalf("Encode reply failed: %v", err)
	}
	original := append([]byte(nil), replyBuf...)

	if _, err := DecodeReplyLazy(secret, replyBuf, req.Authenticator[:]); err != nil {
		t.Fatalf("DecodeReplyLazy failed: %v", err)
	}
	if !bytes.Equal(replyBuf, original) {
		t.Fatalf("DecodeReplyLazy modified the input buffer")
	}

	// A tampered Message-Authenticator must still be rejected. Fix up the
	// Response Authenticator so only the Message-Authenticator check fails.
	tampered := append([]byte(nil), replyBuf...)
	tampered[packetHeaderLen+messageAuthenticatorLen-1] ^= 0xff
	h := md5.New()
	h.Write(tampered[0:4])
	h.Write(req.Authenticator[:])
	h.Write(tampered[20:])
	h.Write([]byte(secret))
	copy(tampered[4:20], h.Sum(nil))
	if _, err := DecodeReplyLazy(secret, tampered, req.Authenticator[:]); err != ErrMessageAuthenticatorCheckFail {
		t.Fatalf("DecodeReplyLazy with tampered Message-Authenticator: got %v, want %v", err, ErrMessageAuthenticatorCheckFail)
	}
	if _, err := DecodeReply(secret, tampered, req.Authenticator[:]); err != ErrMessageAuthenticatorCheckFail {
		t.Fatalf("DecodeReply with tampered Message-Authenticator: got %v, want %v", err, ErrMessageAuthenticatorCheckFail)
	}
}

// A Request Authenticator that happens to start with a zero byte must not be
// replaced by EncodeTo: User-Password was already encrypted with it.
func TestEncodeKeepsAuthenticatorWithLeadingZero(t *testing.T) {
	const secret = "testing123"
	const password = "s3cret-pass"

	p := Request(AccessRequest, secret)
	p.Authenticator[0] = 0
	want := p.Authenticator
	p.AddPassword(password)

	b, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if p.Authenticator != want {
		t.Fatalf("Authenticator changed by Encode:\nwant %x\ngot  %x", want, p.Authenticator)
	}

	req, err := DecodeRequest(secret, b)
	if err != nil {
		t.Fatalf("DecodeRequest failed: %v", err)
	}
	if got := req.GetPassword(); got != password {
		t.Fatalf("GetPassword = %q, want %q", got, password)
	}
}

// A tampered authenticator or body must fail the authenticator check.
func TestAuthenticatorCheckRejectsTampering(t *testing.T) {
	const secret = "testing123"

	req := Request(AccountingRequest, secret)
	req.Identifier = 7
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	reqBuf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(secret, reqBuf)
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	reply := decoded.Reply()
	reply.Code = AccountingResponse
	reply.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("ok")})
	replyBuf, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReply(secret, replyBuf, decoded.Authenticator[:]); err != nil {
		t.Fatalf("valid reply rejected: %v", err)
	}

	cases := []struct {
		name    string
		buf     []byte
		offset  int
		isReply bool
	}{
		{"request authenticator", reqBuf, 4, false},
		{"request body", reqBuf, len(reqBuf) - 1, false},
		{"reply authenticator", replyBuf, 4 + authenticatorLen - 1, true},
		{"reply body", replyBuf, len(replyBuf) - 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Clone(tc.buf)
			buf[tc.offset] ^= 0x01
			if tc.isReply {
				_, err = DecodeReply(secret, buf, decoded.Authenticator[:])
			} else {
				_, err = DecodeRequest(secret, buf)
			}
			if err != ErrAuthenticatorCheckFail {
				t.Fatalf("got %v, want ErrAuthenticatorCheckFail", err)
			}
		})
	}
}

// signRequest builds a request as FreeRADIUS signs it: Message-Authenticator first,
// computed with a zero Request Authenticator, then the Request Authenticator (RFC 5176 section 3.5).
func signRequest(code PacketCode, secret string, attrs []byte) []byte {
	b := make([]byte, packetHeaderLen, packetHeaderLen+messageAuthenticatorLen+len(attrs))
	b[0] = byte(code)
	b[1] = 9
	b = append(b, byte(AttrMessageAuthenticator), messageAuthenticatorLen)
	b = append(b, make([]byte, md5.Size)...)
	b = append(b, attrs...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	h := hmac.New(md5.New, []byte(secret))
	h.Write(b)
	copy(b[packetHeaderLen+2:], h.Sum(nil))
	m := md5.New()
	m.Write(b)
	m.Write([]byte(secret))
	copy(b[4:packetHeaderLen], m.Sum(nil))
	return b
}

// messageAuthenticatorOK checks the first attribute of b, a Message-Authenticator,
// hashing auth in place of the authenticator field.
func messageAuthenticatorOK(secret string, b, auth []byte) bool {
	if b[packetHeaderLen] != byte(AttrMessageAuthenticator) {
		return false
	}
	c := bytes.Clone(b)
	copy(c[4:packetHeaderLen], auth)
	value := c[packetHeaderLen+2 : packetHeaderLen+messageAuthenticatorLen]
	want := bytes.Clone(value)
	clear(value)
	h := hmac.New(md5.New, []byte(secret))
	h.Write(c)
	return hmac.Equal(h.Sum(nil), want)
}

// Accounting, CoA and Disconnect requests hash a zero Request Authenticator into Message-Authenticator.
func TestMessageAuthenticatorZeroVectorRequests(t *testing.T) {
	const secret = "testing123"
	userName := append([]byte{byte(AttrUserName), 7}, "alice"...)

	for _, code := range []PacketCode{AccountingRequest, CoARequest, DisconnectRequest} {
		t.Run(code.String(), func(t *testing.T) {
			b := signRequest(code, secret, userName)
			if _, err := DecodeRequest(secret, b); err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}
			if _, err := DecodeRequestLazy(secret, b); err != nil {
				t.Fatalf("DecodeRequestLazy: %v", err)
			}

			// a bad Message-Authenticator with a valid Request Authenticator
			bad := bytes.Clone(b)
			bad[packetHeaderLen+2] ^= 0xff
			m := md5.New()
			m.Write(bad[:4])
			m.Write(zeroAuthenticator[:])
			m.Write(bad[packetHeaderLen:])
			m.Write([]byte(secret))
			copy(bad[4:packetHeaderLen], m.Sum(nil))
			if _, err := DecodeRequest(secret, bad); err != ErrMessageAuthenticatorCheckFail {
				t.Fatalf("tampered: got %v, want %v", err, ErrMessageAuthenticatorCheckFail)
			}
		})
	}
}

// A Message-Authenticator added to a non-Access packet is filled on encode.
func TestEncodeFillsMessageAuthenticator(t *testing.T) {
	const secret = "testing123"

	for _, code := range []PacketCode{AccountingRequest, CoARequest, DisconnectRequest} {
		t.Run(code.String(), func(t *testing.T) {
			req := Request(code, secret)
			req.AddAVP(AVP{Type: AttrMessageAuthenticator, Value: make([]byte, md5.Size)})
			req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
			b, err := req.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !messageAuthenticatorOK(secret, b, zeroAuthenticator[:]) {
				t.Fatal("request Message-Authenticator not computed with a zero Request Authenticator")
			}
			decoded, err := DecodeRequestWithOptions(secret, b, &DecodeOptions{RequireMessageAuthenticator: true})
			if err != nil {
				t.Fatalf("DecodeRequest: %v", err)
			}

			reply := decoded.Reply()
			reply.Code = code + 1 // Accounting-Response, CoA-ACK, Disconnect-ACK
			reply.AddAVP(AVP{Type: AttrMessageAuthenticator, Value: make([]byte, md5.Size)})
			rb, err := reply.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !messageAuthenticatorOK(secret, rb, b[4:packetHeaderLen]) {
				t.Fatal("reply Message-Authenticator not computed with the Request Authenticator")
			}
			if _, err := DecodeReply(secret, rb, b[4:packetHeaderLen]); err != nil {
				t.Fatalf("DecodeReply: %v", err)
			}
		})
	}
}

// Requests must not decode as replies (they carry no authentication), nor replies as requests.
func TestDecodeRejectsWrongDirection(t *testing.T) {
	const secret = "testing123"
	statusServer, err := Request(StatusServer, secret).Encode()
	if err != nil {
		t.Fatal(err)
	}
	requests := map[string][]byte{
		"Access-Request": rawAccessRequest(1),
		"Status-Server":  statusServer,
	}
	auth := make([]byte, authenticatorLen)
	for name, b := range requests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeReply(secret, b, auth); !errors.Is(err, ErrUnexpectedCode) {
				t.Errorf("DecodeReply: got %v, want %v", err, ErrUnexpectedCode)
			}
			if _, err := DecodeReplyLazy(secret, b, auth); !errors.Is(err, ErrUnexpectedCode) {
				t.Errorf("DecodeReplyLazy: got %v, want %v", err, ErrUnexpectedCode)
			}
			if _, err := DecodeReplyPooled(secret, b, auth); !errors.Is(err, ErrUnexpectedCode) {
				t.Errorf("DecodeReplyPooled: got %v, want %v", err, ErrUnexpectedCode)
			}
		})
	}

	accept, err := Request(AccessRequest, secret).ReplyAccept().Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(secret, accept); !errors.Is(err, ErrUnexpectedCode) {
		t.Errorf("DecodeRequest: got %v, want %v", err, ErrUnexpectedCode)
	}
	if _, err := DecodeRequestLazy(secret, accept); !errors.Is(err, ErrUnexpectedCode) {
		t.Errorf("DecodeRequestLazy: got %v, want %v", err, ErrUnexpectedCode)
	}
	if _, err := DecodeRequestPooled(secret, accept); !errors.Is(err, ErrUnexpectedCode) {
		t.Errorf("DecodeRequestPooled: got %v, want %v", err, ErrUnexpectedCode)
	}
}

// RFC 3579 section 3.2: Access-* packets with EAP-Message must carry Message-Authenticator.
func TestEAPMessageRequiresMessageAuthenticator(t *testing.T) {
	const secret = "testing123"
	eap := AVP{Type: AttrEAPMessage, Value: []byte{2, 1, 0, 5, 1}}

	req := rawRequest(AccessRequest, 1, eap)
	reqAuth := req[4:packetHeaderLen]
	reply := rawRequest(AccessChallenge, 1, eap)
	h := md5.New()
	h.Write(reply[:4])
	h.Write(reqAuth)
	h.Write(reply[packetHeaderLen:])
	h.Write([]byte(secret))
	copy(reply[4:packetHeaderLen], h.Sum(nil))

	decoders := map[string]func() (*Packet, error){
		"request":             func() (*Packet, error) { return DecodeRequest(secret, req) },
		"request pooled":      func() (*Packet, error) { return DecodeRequestPooled(secret, req) },
		"request lazy":        func() (*Packet, error) { return DecodeRequestLazy(secret, req) },
		"request lazy pooled": func() (*Packet, error) { return DecodeRequestLazyPooled(secret, req) },
		"reply":               func() (*Packet, error) { return DecodeReply(secret, reply, reqAuth) },
		"reply pooled":        func() (*Packet, error) { return DecodeReplyPooled(secret, reply, reqAuth) },
		"reply lazy":          func() (*Packet, error) { return DecodeReplyLazy(secret, reply, reqAuth) },
		"reply lazy pooled":   func() (*Packet, error) { return DecodeReplyLazyPooled(secret, reply, reqAuth) },
	}
	for name, decode := range decoders {
		if _, err := decode(); !errors.Is(err, ErrMessageAuthenticatorMissing) {
			t.Errorf("%s: got %v, want %v", name, err, ErrMessageAuthenticatorMissing)
		}
	}
}
