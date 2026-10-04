package radius

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// RFC 5997: Status-Server has a random authenticator and a leading Message-Authenticator.
func TestStatusServerEncodeDecode(t *testing.T) {
	const secret = "testing123"
	req := NewRadClient("", secret).NewStatusServer()
	req.Identifier = 3
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if req.Authenticator == [authenticatorLen]byte{} {
		t.Fatal("Status-Server authenticator not generated")
	}
	if !bytes.Equal(b[4:packetHeaderLen], req.Authenticator[:]) {
		t.Fatal("encoded authenticator differs from packet authenticator")
	}
	if b[packetHeaderLen] != byte(AttrMessageAuthenticator) || b[packetHeaderLen+1] != messageAuthenticatorLen {
		t.Fatalf("expected leading Message-Authenticator, got type=%d len=%d", b[packetHeaderLen], b[packetHeaderLen+1])
	}

	opts := &DecodeOptions{RequireMessageAuthenticator: true}
	decoders := map[string]func() (*Packet, error){
		"normal": func() (*Packet, error) { return DecodeRequestWithOptions(secret, b, opts) },
		"pooled": func() (*Packet, error) { return DecodeRequestPooledWithOptions(secret, b, opts) },
		"lazy":   func() (*Packet, error) { return DecodeRequestLazyWithOptions(secret, b, opts) },
	}
	for name, decode := range decoders {
		p, err := decode()
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if p.Code != StatusServer || p.Identifier != 3 || p.Authenticator != req.Authenticator {
			t.Fatalf("%s: got code=%v id=%d", name, p.Code, p.Identifier)
		}
		if !p.HasAVP(AttrMessageAuthenticator) {
			t.Fatalf("%s: Message-Authenticator missing", name)
		}
	}
}

// RFC 5997 section 3: Status-Server without a valid Message-Authenticator is discarded.
func TestStatusServerRequiresMessageAuthenticator(t *testing.T) {
	const secret = "testing123"
	raw := rawRequest(StatusServer, 1)
	if _, err := DecodeRequest(secret, raw); !errors.Is(err, ErrMessageAuthenticatorMissing) {
		t.Errorf("normal: got %v, want %v", err, ErrMessageAuthenticatorMissing)
	}
	if _, err := DecodeRequestPooled(secret, raw); !errors.Is(err, ErrMessageAuthenticatorMissing) {
		t.Errorf("pooled: got %v, want %v", err, ErrMessageAuthenticatorMissing)
	}
	if _, err := DecodeRequestLazy(secret, raw); !errors.Is(err, ErrMessageAuthenticatorMissing) {
		t.Errorf("lazy: got %v, want %v", err, ErrMessageAuthenticatorMissing)
	}

	b, err := Request(StatusServer, secret).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeRequest("wrong", b); !errors.Is(err, ErrMessageAuthenticatorCheckFail) {
		t.Errorf("wrong secret: got %v, want %v", err, ErrMessageAuthenticatorCheckFail)
	}
}

// Replies to Status-Server verify against its request authenticator.
func TestStatusServerReplies(t *testing.T) {
	const secret = "testing123"
	req := Request(StatusServer, secret)
	if _, err := req.Encode(); err != nil {
		t.Fatalf("Encode request: %v", err)
	}
	opts := &DecodeOptions{RequireMessageAuthenticator: true}
	for _, reply := range []*Packet{req.ReplyAccept(), req.ReplyAccountingResponse()} {
		b, err := reply.Encode()
		if err != nil {
			t.Fatalf("%v: Encode: %v", reply.Code, err)
		}
		got, err := DecodeReplyWithOptions(secret, b, req.Authenticator[:], opts)
		if err != nil {
			t.Fatalf("%v: decode: %v", reply.Code, err)
		}
		if got.Code != reply.Code {
			t.Fatalf("got %v, want %v", got.Code, reply.Code)
		}
	}
}

// statusHandler answers Status-Server like an auth or accounting port.
func statusHandler(replyCode PacketCode) Service {
	return HandlerFunc(func(ctx context.Context, req *Packet) *Packet {
		if req.Code != StatusServer {
			return nil
		}
		return req.replyWithCode(replyCode)
	})
}

func TestServerStatusServer(t *testing.T) {
	const secret = "testing123"
	for _, code := range []PacketCode{AccessAccept, AccountingResponse} {
		srv := NewServer("127.0.0.1:0", secret, statusHandler(code))
		addr, _ := startTestServer(t, srv)

		client := NewRadClient(addr, secret)
		client.SetTimeout(noReplyTimeout)
		reply, err := client.Send(client.NewStatusServer())
		if err != nil {
			t.Fatalf("%v: Send: %v", code, err)
		}
		if reply.Code != code {
			t.Fatalf("got %v, want %v", reply.Code, code)
		}

		if _, err := exchangeRaw(t, addr, rawRequest(StatusServer, 1), noReplyTimeout); err == nil {
			t.Errorf("%v: Status-Server without Message-Authenticator got a reply", code)
		}
	}
}
