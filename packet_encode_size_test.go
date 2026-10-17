package radius

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fillTo adds Class attributes until the packet encodes to exactly n bytes.
func fillTo(t *testing.T, p *Packet, n int) {
	t.Helper()
	size := packetHeaderLen + len(p.RawAVPs)
	if p.Code.hasMessageAuthenticator() && !p.HasAVP(AttrMessageAuthenticator) {
		size += messageAuthenticatorLen
	}
	for _, a := range p.AVPs {
		size += 2 + len(a.Value)
	}
	for size < n {
		l := min(n-size, 255)
		if r := n - size - l; r > 0 && r < 2 {
			l-- // leave room for a non-empty last one
		}
		p.AddAVP(AVP{Type: AttrClass, Value: make([]byte, l-2)})
		size += l
	}
}

func TestAVPEncodeShortBuffer(t *testing.T) {
	a := AVP{Type: AttrUserName, Value: []byte("alice")}
	for _, n := range []int{0, 1, 6} {
		if _, err := a.Encode(make([]byte, n)); !errors.Is(err, ErrBufferTooSmall) {
			t.Errorf("Encode into %d bytes: err = %v, want ErrBufferTooSmall", n, err)
		}
	}
	b := make([]byte, 7)
	if n, err := a.Encode(b); err != nil || n != 7 || !bytes.Equal(b, []byte("\x01\x07alice")) {
		t.Errorf("Encode into 7 bytes = %d, %v, %q", n, err, b)
	}
}

// Packets over 4096 bytes (RFC 2865 §3) are refused instead of panicking.
func TestEncodeTooLarge(t *testing.T) {
	const secret = "testing123"
	big := func() *Packet {
		p := Request(AccessRequest, secret)
		for range 20 {
			p.AddAVP(AVP{Type: AttrClass, Value: make([]byte, 253)})
		}
		return p
	}
	eap := Request(AccessRequest, secret)
	eap.SetEAPMessage(&EapPacket{Code: EapCodeResponse, Type: EapTypeIdentity, Data: make([]byte, 5000)})

	lazy := Request(AccountingRequest, secret)
	fillTo(t, lazy, maxPacketLen)
	buf, err := lazy.Encode()
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := DecodeRequestLazy(secret, buf)
	if err != nil {
		t.Fatal(err)
	}
	forwarded.AddAVP(AVP{Type: AttrProxyState, Value: []byte("proxy")})

	for name, p := range map[string]*Packet{"20 x 253 bytes": big(), "EAP 5000 bytes": eap, "Proxy-State on full packet": forwarded} {
		if _, err := p.Encode(); !errors.Is(err, ErrPacketTooLarge) {
			t.Errorf("%s: Encode err = %v, want ErrPacketTooLarge", name, err)
		}
		if _, err := p.EncodeTo(make([]byte, 2*maxPacketLen)); !errors.Is(err, ErrPacketTooLarge) {
			t.Errorf("%s: EncodeTo(8192) err = %v, want ErrPacketTooLarge", name, err)
		}
		// 64 KiB would overflow the Length field
		if _, err := p.EncodeTo(make([]byte, 1<<17)); !errors.Is(err, ErrPacketTooLarge) {
			t.Errorf("%s: EncodeTo(128K) err = %v, want ErrPacketTooLarge", name, err)
		}
	}

	client := NewRadClient("127.0.0.1:1", secret)
	client.SetTimeout(100 * time.Millisecond)
	if _, err := client.Send(big()); !errors.Is(err, ErrPacketTooLarge) {
		t.Errorf("RadClient.Send err = %v, want ErrPacketTooLarge", err)
	}
}

func TestEncodeToSmallBuffer(t *testing.T) {
	p := Request(AccessRequest, "testing123")
	p.AddAVP(AVP{Type: AttrUserName, Value: make([]byte, 100)})
	for _, n := range []int{0, 19, 20, 37, 60, 139} {
		if _, err := p.EncodeTo(make([]byte, n)); !errors.Is(err, ErrBufferTooSmall) {
			t.Errorf("EncodeTo(%d) err = %v, want ErrBufferTooSmall", n, err)
		}
	}
	if n, err := p.EncodeTo(make([]byte, 140)); err != nil || n != 140 {
		t.Errorf("EncodeTo(140) = %d, %v, want 140", n, err)
	}
}

// A packet of exactly 4096 bytes encodes and decodes.
func TestEncodeMaxSize(t *testing.T) {
	const secret = "testing123"
	for _, code := range []PacketCode{AccessRequest, AccountingRequest} {
		p := Request(code, secret)
		fillTo(t, p, maxPacketLen)
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("%v: Encode: %v", code, err)
		}
		if len(b) != maxPacketLen || binary.BigEndian.Uint16(b[2:4]) != maxPacketLen {
			t.Fatalf("%v: encoded %d bytes, Length %d", code, len(b), binary.BigEndian.Uint16(b[2:4]))
		}
		if _, err := DecodeRequest(secret, b); err != nil {
			t.Errorf("%v: DecodeRequest: %v", code, err)
		}
		p.AddAVP(AVP{Type: AttrProxyState, Value: []byte{1}})
		if _, err := p.Encode(); !errors.Is(err, ErrPacketTooLarge) {
			t.Errorf("%v: 4099 bytes: err = %v, want ErrPacketTooLarge", code, err)
		}
	}
}

// An oversized reply is an encode error in the server, not a recovered panic.
func TestServerReplyTooLarge(t *testing.T) {
	const secret = "testing123"
	h := useRecordLogger(t)
	srv := NewServer("127.0.0.1:0", secret, HandlerFunc(func(_ context.Context, req *Packet) *Packet {
		reply := req.ReplyAccountingResponse()
		fillTo(t, reply, maxPacketLen+1)
		return reply
	}))
	addr, _ := startTestServer(t, srv)

	client := NewRadClient(addr, secret)
	client.SetTimeout(200 * time.Millisecond)
	if _, err := client.Send(Request(AccountingRequest, secret)); err == nil {
		t.Fatal("got a reply")
	}
	srv.Stop() // waits for the handler
	if h.count(slog.LevelError, "encode reply") != 1 || h.count(slog.LevelError, "panic") != 0 {
		t.Errorf("log:\n%s", h.all())
	}
	if !strings.Contains(h.all(), ErrPacketTooLarge.Error()) {
		t.Errorf("log misses ErrPacketTooLarge:\n%s", h.all())
	}
}
