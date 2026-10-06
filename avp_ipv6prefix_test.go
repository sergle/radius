package radius

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestAvpIPv6PrefixDecode(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  string
	}{
		{"full", []byte{0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "2001:db8::/64"},
		{"truncated", []byte{0, 32, 0x20, 0x01, 0x0d, 0xb8}, "2001:db8::/32"},
		{"partial byte", []byte{0, 60, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x10}, "2001:db8:0:10::/60"},
		{"zero length", []byte{0, 0}, "::/0"},
		{"host route", []byte{0, 128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1/128"},
		{"short prefix bytes", []byte{0, 64}, "::/64"},
		{"short host route", []byte{0, 128, 0x20, 0x01}, "2001::/128"},
		{"reserved byte set", []byte{0xff, 32, 0x20, 0x01, 0x0d, 0xb8}, "2001:db8::/32"},
		{"host bits kept", []byte{0, 32, 0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff}, "2001:db8:ffff::/32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AVP{Type: AttrFramedIPv6Prefix, Value: tt.value}
			if got := avpIPv6Prefix.String(nil, a); got != tt.want {
				t.Errorf("String = %q, want %q", got, tt.want)
			}
			if got := avpIPv6Prefix.Value(nil, a); got != netip.MustParsePrefix(tt.want) {
				t.Errorf("Value = %v, want %v", got, tt.want)
			}
			if got, ok := a.Decode(nil).(netip.Prefix); !ok || got != netip.MustParsePrefix(tt.want) {
				t.Errorf("AVP.Decode = %#v, want %v", a.Decode(nil), tt.want)
			}
			if got := a.String(); got != "AVP type: Framed-IPv6-Prefix "+tt.want {
				t.Errorf("AVP.String = %q", got)
			}
			if got := GetDefaultDictionary().DecodeAVPValue(nil, a); got != tt.want {
				t.Errorf("DecodeAVPValue = %q, want %q", got, tt.want)
			}
		})
	}
}

// Malformed values are shown as raw bytes and decode to the zero Prefix.
func TestAvpIPv6PrefixMalformed(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0}},
		{"19 bytes", append([]byte{0, 64}, make([]byte, 17)...)},
		{"length 129", append([]byte{0, 129}, make([]byte, 16)...)},
	}
	d := GetDefaultDictionary()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AVP{Type: AttrFramedIPv6Prefix, Value: tt.value}
			raw := avpBinary.String(nil, a)
			if got := avpIPv6Prefix.String(nil, a); got != raw {
				t.Errorf("String = %q, want %q", got, raw)
			}
			if got := avpIPv6Prefix.Value(nil, a); got != (netip.Prefix{}) {
				t.Errorf("Value = %v, want zero Prefix", got)
			}
			if got := d.DecodeAVPValue(nil, a); got != raw {
				t.Errorf("DecodeAVPValue = %q, want %q", got, raw)
			}
		})
	}
}

// FromString emits all 16 prefix bytes and clears host bits, as FreeRADIUS v3.2 does.
func TestAvpIPv6PrefixFromString(t *testing.T) {
	tests := []struct {
		in   string
		want []byte
	}{
		{"2001:db8::/64", []byte{0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"2001:db8::1/64", []byte{0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"2001:db8:0:1f::/60", []byte{0, 60, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"::/0", make([]byte, 18)},
		{"2001:db8::1/128", []byte{0, 128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"2001:db8::1", []byte{0, 128, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"*", append([]byte{0, 128}, make([]byte, 16)...)},
		{"2001:db8::/064", []byte{0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"::ffff:10.0.0.0/104", []byte{0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 0}},
		{"::ffff:1.2.3.4", []byte{0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}},
		{"2001:db8::/00000000000000000000064", []byte{0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		if got := avpIPv6Prefix.FromString(tt.in); !bytes.Equal(got, tt.want) {
			t.Errorf("FromString(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"", "garbage", "2001:db8::/129", "10.0.0.0/8", "10.0.0.1", "fe80::%eth0/64", "fe80::1%eth0", "2001:db8::/-1", "2001:db8::/", "2001:db8::/+64", "2001:db8::/ 64", "*/64",
		"2001:db8::/99999999999999999999999", "2001:db8::/1e2", "2001:db8::/\u0666\u0664", "2001:db8::/0x40", "2001:db8::/-0", "2001:db8::/64/1", "2001:db8::/64 ", "*/128", "[2001:db8::]/32"} {
		if got := avpIPv6Prefix.FromString(in); got != nil {
			t.Errorf("FromString(%q) = %v, want nil", in, got)
		}
	}
}

// The IPv4-mapped form survives a round trip.
func TestAvpIPv6PrefixMappedRoundTrip(t *testing.T) {
	const mapped = "::ffff:10.0.0.0/104"
	a := AVP{Type: AttrFramedIPv6Prefix, Value: avpIPv6Prefix.FromString(mapped)}
	if got := avpIPv6Prefix.String(nil, a); got != mapped {
		t.Errorf("String = %q, want %q", got, mapped)
	}
}

func TestIPv6PrefixParseAVP(t *testing.T) {
	d := GetDefaultDictionary()
	avp, err := d.ParseAVP("Framed-IPv6-Prefix", "2001:db8::/64")
	if err != nil {
		t.Fatal(err)
	}
	if avp.Type != AttrFramedIPv6Prefix || d.DecodeAVPValue(nil, avp) != "2001:db8::/64" {
		t.Errorf("ParseAVP = %v", avp)
	}
	if _, err := d.ParseAVP("Framed-IPv6-Prefix", "10.0.0.0/8"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseAVP IPv4: err = %v", err)
	}

	td := loadTLVDict(t, `
VENDOR V 9999
BEGIN-VENDOR V
ATTRIBUTE P 1 ipv6prefix
ATTRIBUTE A 2 tlv
ATTRIBUTE A-P 2.1 ipv6prefix
END-VENDOR V
`)
	vsa, err := td.ParseVSA("V", "P", "2001:db8::/48")
	if err != nil {
		t.Fatal(err)
	}
	if got := td.DecodeAVPValue(nil, vsa.ToAVP()); got != "{Vendor:V #9999, Attr: P #1, Value: 2001:db8::/48}" {
		t.Errorf("DecodeAVPValue VSA = %q", got)
	}
	tlv, err := td.ParseTLV("V", "A", TLVValue{Name: "A-P", Value: "2001:db8::/48"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := td.GetTLVString(&Packet{AVPs: []AVP{tlv}}, "V", "A-P"); !ok || got != "2001:db8::/48" {
		t.Errorf("GetTLVString = %q, %v", got, ok)
	}
	if _, err := td.ParseTLV("V", "A", TLVValue{Name: "A-P", Value: "garbage"}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseTLV invalid: err = %v", err)
	}

	// malformed values in a VSA or a TLV are shown as raw bytes
	bad := []byte{0, 129}
	if got := td.DecodeAVPValue(nil, VSA{Vendor: 9999, Type: 1, Value: bad}.ToAVP()); got != "{Vendor:V #9999, Attr: P #1, Value: []byte{0x0, 0x81}}" {
		t.Errorf("DecodeAVPValue malformed VSA = %q", got)
	}
	badTLV := VSA{Vendor: 9999, Type: 2, Value: append([]byte{1, byte(tlvHeaderLen + len(bad))}, bad...)}.ToAVP()
	if got, ok := td.GetTLVString(&Packet{AVPs: []AVP{badTLV}}, "V", "A-P"); !ok || got != "[]byte{0x0, 0x81}" {
		t.Errorf("GetTLVString malformed = %q, %v", got, ok)
	}
}

// A template drops an invalid prefix.
func TestIPv6PrefixTemplateInvalid(t *testing.T) {
	rt, err := GetDefaultDictionary().CreateRequestTemplate(AccessRequest, "Framed-IPv6-Prefix")
	if err != nil {
		t.Fatal(err)
	}
	p := Request(AccessRequest, "secret")
	rt.Fill(p, "garbage")
	if p.HasAVP(AttrFramedIPv6Prefix) {
		t.Errorf("invalid prefix added: %v", p.AVPs)
	}
	rt.Fill(p, "2001:db8::/64")
	if !p.HasAVP(AttrFramedIPv6Prefix) {
		t.Error("valid prefix not added")
	}
}
