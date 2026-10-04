package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// RFC 2868 tagged values as a server sends them (FreeRADIUS "Tunnel-Type:1 = VLAN").
func taggedVLANPacket() *Packet {
	p := Request(AccessRequest, "testing123").ReplyAccept()
	p.AddAVP(AVP{Type: AttrTunnelType, Value: []byte{1, 0, 0, byte(TunnelTypeEnumVLAN)}})
	p.AddAVP(AVP{Type: AttrTunnelMediumType, Value: []byte{1, 0, 0, byte(TunnelMediumTypeEnum802)}})
	p.AddAVP(AVP{Type: AttrTunnelPrivateGroupID, Value: append([]byte{1}, "100"...)})
	return p
}

func TestGetVLANTagged(t *testing.T) {
	if id, ok := taggedVLANPacket().GetVLAN(); !ok || id != 100 {
		t.Errorf("GetVLAN = %d, %v; want 100, true", id, ok)
	}
}

func TestDecodeTaggedValues(t *testing.T) {
	d := GetDefaultDictionary()
	p := taggedVLANPacket()

	tt := p.GetAVP(AttrTunnelType)
	if got := tt.Decode(p); got != uint32(TunnelTypeEnumVLAN) {
		t.Errorf("Tunnel-Type Decode = %#v, want %d", got, TunnelTypeEnumVLAN)
	}
	if got := d.DecodeAVPValue(p, *tt); got != "VLAN (tag 1)" {
		t.Errorf("Tunnel-Type DecodeAVPValue = %q, want %q", got, "VLAN (tag 1)")
	}

	for _, tc := range []struct {
		value []byte
		want  string
	}{
		{append([]byte{1}, "100"...), "100"},
		{[]byte("100"), "100"},          // first byte > 0x1F: no tag
		{[]byte{0, 0x05, 'x'}, "\x05x"}, // explicit tag 0
		{[]byte{0x1f}, ""},              // tag only
	} {
		a := AVP{Type: AttrTunnelPrivateGroupID, Value: tc.value}
		if got := a.Decode(p); got != tc.want {
			t.Errorf("Tunnel-Private-Group-ID %x Decode = %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestParseTaggedAVP(t *testing.T) {
	d := GetDefaultDictionary()
	for _, tc := range []struct {
		name, value string
		want        []byte
	}{
		{"Tunnel-Type", "VLAN", []byte{0, 0, 0, 13}},
		{"Tunnel-Type:1", "VLAN", []byte{1, 0, 0, 13}},
		{"Tunnel-Medium-Type:31", "802", []byte{31, 0, 0, 6}},
		{"Tunnel-Private-Group-ID", "100", []byte("100")},
		{"Tunnel-Private-Group-ID:2", "100", append([]byte{2}, "100"...)},
		{"Tunnel-Private-Group-ID", "\x05x", []byte{0, 5, 'x'}},
	} {
		a, err := d.ParseAVP(tc.name, tc.value)
		if err != nil || !bytes.Equal(a.Value, tc.want) {
			t.Errorf("ParseAVP(%q, %q) = %v, %v; want %v", tc.name, tc.value, a.Value, err, tc.want)
		}
	}
	for _, tc := range []struct{ name, value string }{
		{"Tunnel-Type:32", "VLAN"},
		{"Tunnel-Type:x", "VLAN"},
		{"User-Name:1", "bob"},
	} {
		if _, err := d.ParseAVP(tc.name, tc.value); !errors.Is(err, ErrInvalidTag) {
			t.Errorf("ParseAVP(%q): err = %v, want ErrInvalidTag", tc.name, err)
		}
	}
	if _, err := d.ParseAVP("Tunnel-Preference", "16777216"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("24-bit overflow: err = %v, want ErrInvalidValue", err)
	}
}

func TestTemplateTagged(t *testing.T) {
	const secret = "testing123"
	d := GetDefaultDictionary()
	rt, err := d.CreateRequestTemplate(AccessAccept, "Tunnel-Type:1", "Tunnel-Private-Group-ID:1", "Tunnel-Password:2")
	if err != nil {
		t.Fatalf("CreateRequestTemplate: %v", err)
	}
	req := Request(AccessRequest, secret)
	reply := req.ReplyAccept()
	rt.Fill(reply, "VLAN", "200", "tun-pw")

	if a := reply.GetAVP(AttrTunnelType); a == nil || !bytes.Equal(a.Value, []byte{1, 0, 0, 13}) {
		t.Errorf("Tunnel-Type = %v, want [1 0 0 13]", a)
	}
	if a := reply.GetAVP(AttrTunnelPrivateGroupID); a == nil || !bytes.Equal(a.Value, append([]byte{1}, "200"...)) {
		t.Errorf("Tunnel-Private-Group-ID = %v, want tag 1 + \"200\"", a)
	}
	if tag, pw, ok := reply.GetTunnelPassword(); !ok || tag != 2 || pw != "tun-pw" {
		t.Errorf("GetTunnelPassword = %d, %q, %v; want 2, tun-pw, true", tag, pw, ok)
	}
	if _, err := d.CreateRequestTemplate(AccessAccept, "User-Name:1"); err == nil || !strings.Contains(err.Error(), "tag") {
		t.Errorf("tag on untagged attribute: err = %v", err)
	}
}
