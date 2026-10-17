package radius

import (
	"reflect"
	"testing"
)

// fullPacket returns a packet with every field set.
func fullPacket() *Packet {
	p := &Packet{
		Secret:      "testing123",
		Code:        AccessAccept,
		Identifier:  42,
		AVPs:        []AVP{{Type: AttrUserName, Value: []byte("alice")}},
		RawAVPs:     []byte{byte(AttrUserName), 5, 'b', 'o', 'b'},
		ClientAddr:  "192.0.2.1:1812",
		requestAuth: [authenticatorLen]byte{1, 2, 3},
		salts:       []uint16{0x8123},
		masked:      true,
	}
	p.Authenticator = [authenticatorLen]byte{4, 5, 6}
	return p
}

// Every non-zero field must survive Copy, so new fields are not forgotten.
func TestPacketCopyAllFields(t *testing.T) {
	src := fullPacket()
	sv := reflect.ValueOf(src).Elem()
	for i := 0; i < sv.NumField(); i++ {
		// chain is formatting state of the copy String makes, never copied
		if sv.Type().Field(i).Name == "chain" {
			continue
		}
		if sv.Field(i).IsZero() {
			t.Fatalf("fullPacket leaves field %s zero", sv.Type().Field(i).Name)
		}
	}

	dst := src.Copy()
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("copy differs:\nsrc %+v\ndst %+v", src, dst)
	}
}

// The copy must not share mutable memory with the original.
func TestPacketCopyIndependent(t *testing.T) {
	src := fullPacket()
	dst := src.Copy()
	want := fullPacket()

	src.AVPs[0].Value[0] = 'X'
	src.AVPs[0].Type = AttrReplyMessage
	src.RawAVPs[2] = 'X'
	src.ClientAddr = "198.51.100.1:1812"
	src.Authenticator[0] = 0xff
	src.requestAuth[0] = 0xff
	src.salts[0] = 0xffff

	if !reflect.DeepEqual(dst, want) {
		t.Errorf("copy changed with original:\ngot  %+v\nwant %+v", dst, want)
	}
}

// encodedRequest returns an Access-Request with a User-Name.
func encodedRequest(t *testing.T, secret string) []byte {
	t.Helper()
	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	b, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func TestPacketCopyLazySurvivesBufferReuse(t *testing.T) {
	const secret = "testing123"
	buf := encodedRequest(t, secret)

	p, err := DecodeRequestLazy(secret, buf)
	if err != nil {
		t.Fatalf("DecodeRequestLazy: %v", err)
	}
	p.ClientAddr = "192.0.2.1:1812"
	cp := p.Copy()

	for i := range buf {
		buf[i] = 0
	}

	if got := cp.GetUsername(); got != "alice" {
		t.Errorf("User-Name %q, want alice", got)
	}
	if !cp.HasAVP(AttrMessageAuthenticator) {
		t.Error("Message-Authenticator lost")
	}
	if cp.ClientAddr != "192.0.2.1:1812" {
		t.Errorf("ClientAddr %q", cp.ClientAddr)
	}
}

func TestPacketCopyPooledSurvivesRelease(t *testing.T) {
	const secret = "testing123"
	buf := encodedRequest(t, secret)

	p, err := DecodeRequestPooled(secret, buf)
	if err != nil {
		t.Fatalf("DecodeRequestPooled: %v", err)
	}
	p.ClientAddr = "192.0.2.1:1812"
	auth := p.Authenticator
	cp := p.Copy()
	p.Release()

	for i := range buf {
		buf[i] = 0
	}
	// reuse the released packet's slots
	for i := 0; i < 4; i++ {
		q, err := DecodeRequestPooled(secret, encodedRequest(t, secret))
		if err != nil {
			t.Fatalf("DecodeRequestPooled: %v", err)
		}
		q.AVPs[0].Value[0] = 'X'
		q.Release()
	}

	if cp.Secret != secret || cp.Code != AccessRequest || cp.Authenticator != auth {
		t.Errorf("header lost: %+v", cp)
	}
	if got := cp.GetUsername(); got != "alice" {
		t.Errorf("User-Name %q, want alice", got)
	}
	if cp.ClientAddr != "192.0.2.1:1812" {
		t.Errorf("ClientAddr %q", cp.ClientAddr)
	}
}
