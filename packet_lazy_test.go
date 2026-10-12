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
