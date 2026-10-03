package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
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
	b, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Message-Authenticator is type 80 with length 18 and is appended by EncodeTo
	// for Access-* packets in this library.
	if len(b) < 20+18 {
		t.Fatalf("encoded packet too short: %d", len(b))
	}
	last := b[len(b)-18:]
	if last[0] != byte(AttrMessageAuthenticator) || last[1] != 18 {
		t.Fatalf("expected trailing Message-Authenticator AVP, got type=%d len=%d", last[0], last[1])
	}

	withoutMA := append([]byte(nil), b[:len(b)-18]...)
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
	tampered[len(tampered)-1] ^= 0xff
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
