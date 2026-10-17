package radius

import (
	"strings"
	"testing"
)

func lazyTestPacket(t *testing.T) *Packet {
	t.Helper()
	p := Request(AccountingRequest, "secret")
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte("bob")})
	p.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("a")})
	p.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("b")})
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := DecodeRequestLazy("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	return lazy
}

func avpTypes(p *Packet) []AttributeType {
	var types []AttributeType
	p.EachAVP(func(a AVP) bool {
		types = append(types, a.Type)
		return true
	})
	return types
}

func TestLazyPacketAddAVP(t *testing.T) {
	p := lazyTestPacket(t)
	p.AddAVP(AVP{Type: AttrNASIdentifier, Value: []byte("nas")})

	if !p.HasAVP(AttrUserName) || p.GetUsername() != "bob" {
		t.Errorf("User-Name lost after AddAVP")
	}
	if got := avpTypes(p); len(got) != 4 || got[0] != AttrUserName || got[3] != AttrNASIdentifier {
		t.Errorf("EachAVP = %v", got)
	}
	if s := p.String(); !strings.Contains(s, "bob") || !strings.Contains(s, "nas") {
		t.Errorf("String() misses attributes:\n%s", s)
	}

	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRequest("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := avpTypes(dec); len(got) != 4 || dec.GetUsername() != "bob" || dec.GetNASIdentifier() != "nas" {
		t.Errorf("re-encoded attributes = %v", got)
	}
}

func TestLazyPacketSetAVP(t *testing.T) {
	p := lazyTestPacket(t)
	p.SetAVP(AVP{Type: AttrReplyMessage, Value: []byte("c")})

	got := avpTypes(p)
	if len(got) != 2 || got[0] != AttrUserName || got[1] != AttrReplyMessage {
		t.Fatalf("EachAVP = %v", got)
	}
	if v := p.GetAVP(AttrReplyMessage); v == nil || string(v.Value) != "c" {
		t.Errorf("Reply-Message = %v", v)
	}
}

func TestLazyPacketDeleteAVP(t *testing.T) {
	p := lazyTestPacket(t)
	p.DeleteAVP(p.GetAVP(AttrReplyMessage))
	if got := avpTypes(p); len(got) != 2 || got[0] != AttrUserName || string(p.GetAVP(AttrReplyMessage).Value) != "b" {
		t.Errorf("EachAVP = %v", got)
	}
}

func TestLazyGetAVPMissNoAlloc(t *testing.T) {
	p := lazyTestPacket(t)
	allocs := testing.AllocsPerRun(100, func() {
		if p.HasAVP(AttrNASIPAddress) || p.GetAVP(AttrNASIPAddress) != nil {
			t.Fatal("unexpected attribute")
		}
	})
	if allocs != 0 {
		t.Errorf("allocs = %v, want 0", allocs)
	}
}

func TestDecodeLazyPooled(t *testing.T) {
	const secret = "secret"
	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("bob")})
	buf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// a pooled packet used before must come back with no parsed AVPs
	used, err := DecodeRequestPooled(secret, buf)
	if err != nil {
		t.Fatal(err)
	}
	used.Release()

	p, err := DecodeRequestLazyPooled(secret, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AVPs) != 0 || len(p.RawAVPs) == 0 || p.GetUsername() != "bob" || p.Secret != secret {
		t.Errorf("AVPs %v, RawAVPs %v, User-Name %q, Secret %q", p.AVPs, p.RawAVPs, p.GetUsername(), p.Secret)
	}
	p.Release()

	// no Message-Authenticator: the HMAC check allocates
	raw := getLargeRawPacket()
	allocs := testing.AllocsPerRun(100, func() {
		p, err := DecodeRequestLazyPooled(secret, raw)
		if err != nil {
			t.Fatal(err)
		}
		p.Release()
	})
	if allocs != 0 {
		t.Errorf("allocs = %v, want 0", allocs)
	}

	if p, err := DecodeRequestLazyPooled("wrong", buf[:10]); p != nil || err == nil {
		t.Errorf("short packet: got %v, %v; want nil, error", p, err)
	}
}
