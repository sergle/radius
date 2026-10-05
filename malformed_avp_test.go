package radius

import (
	"runtime/debug"
	"strings"
	"testing"
)

const malformedTestVendorDict = `
VENDOR		TestVendor	9999
BEGIN-VENDOR	TestVendor
ATTRIBUTE	Test-Int	1	integer
VALUE		Test-Int	One	1
ATTRIBUTE	Test-Byte	2	byte
VALUE		Test-Byte	One	1
ATTRIBUTE	Test-Short	3	short
ATTRIBUTE	Test-Signed	4	signed
END-VENDOR	TestVendor
`

// malformedAVPs pass the attribute-length walk but carry values too short for their type.
var malformedAVPs = []struct {
	name string
	avp  AVP
	want string // expected DecodeAVPValue output; "" means only check for panics
}{
	{"Session-Timeout 1 byte", AVP{AttrSessionTimeout, []byte{1}}, "[]byte{0x1}"},
	{"NAS-Port empty", AVP{AttrNASPort, []byte{}}, "[]byte{}"},
	{"NAS-Port 3 bytes", AVP{AttrNASPort, []byte{0, 0, 1}}, "[]byte{0x0, 0x0, 0x1}"},
	{"Acct-Status-Type 2 bytes", AVP{AttrAcctStatusType, []byte{0, 1}}, "[]byte{0x0, 0x1}"},
	{"NAS-Port-Type 1 byte", AVP{AttrNASPortType, []byte{5}}, ""},
	{"Service-Type 1 byte", AVP{AttrServiceType, []byte{2}}, ""},
	{"Tunnel-Type 2 bytes", AVP{AttrTunnelType, []byte{0, 13}}, ""},
	{"NAS-IP-Address 1 byte", AVP{AttrNASIPAddress, []byte{10}}, ""},
	{"NAS-IP-Address 3 bytes", AVP{AttrNASIPAddress, []byte{10, 0, 0}}, ""},
	{"NAS-IPv6-Address 5 bytes", AVP{AttrNASIPv6Address, []byte{0x20, 1, 0xd, 0xb8, 0}}, ""},
	{"Vendor-Specific empty", AVP{AttrVendorSpecific, []byte{}}, "[]byte{}"},
	{"Vendor-Specific 2 bytes", AVP{AttrVendorSpecific, []byte{0, 0}}, "[]byte{0x0, 0x0}"},
	{"Vendor-Specific header only", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 1}}, "[]byte{0x0, 0x0, 0x27, 0xf, 0x1}"},
	{"Vendor-Specific bogus sub-length", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 1, 10, 0, 0}},
		"[]byte{0x0, 0x0, 0x27, 0xf, 0x1, 0xa, 0x0, 0x0}"},
	{"Vendor-Specific sub-length 1", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 1, 1}}, "[]byte{0x0, 0x0, 0x27, 0xf, 0x1, 0x1}"},
	{"Vendor-Specific short integer", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 1, 4, 0, 1}},
		"{Vendor:TestVendor #9999, Attr: Test-Int #1, Value: []byte{0x0, 0x1}}"},
	{"Vendor-Specific empty byte", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 2, 2}},
		"{Vendor:TestVendor #9999, Attr: Test-Byte #2, Value: []byte{}}"},
	{"Vendor-Specific long byte", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 2, 4, 0, 1}},
		"{Vendor:TestVendor #9999, Attr: Test-Byte #2, Value: []byte{0x0, 0x1}}"},
	{"Vendor-Specific short short", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 3, 3, 1}},
		"{Vendor:TestVendor #9999, Attr: Test-Short #3, Value: []byte{0x1}}"},
	{"Vendor-Specific short signed", AVP{AttrVendorSpecific, []byte{0, 0, 0x27, 0x0f, 4, 5, 0xff, 0xff, 0xff}},
		"{Vendor:TestVendor #9999, Attr: Test-Signed #4, Value: []byte{0xff, 0xff, 0xff}}"},
	{"User-Password 5 bytes", AVP{AttrUserPassword, []byte{1, 2, 3, 4, 5}}, ""},
	{"EAP-Message 2 bytes", AVP{AttrEAPMessage, []byte{2, 0}}, ""},
	{"CHAP-Password 3 bytes", AVP{AttrCHAPPassword, []byte{1, 2, 3}}, ""},
}

func newMalformedTestDictionary(t *testing.T) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.LoadBuiltin(); err != nil {
		t.Fatal(err)
	}
	if err := d.loadReader("malformed_test", strings.NewReader(malformedTestVendorDict)); err != nil {
		t.Fatal(err)
	}
	return d
}

// mustNotPanic runs f and reports a panic as a test error.
func mustNotPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v\n%s", what, r, debug.Stack())
		}
	}()
	f()
}

func TestMalformedAVPNoPanic(t *testing.T) {
	d := newMalformedTestDictionary(t)
	p := Request(AccessRequest, "secret")

	for _, tc := range malformedAVPs {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.avp
			mustNotPanic(t, "AVP.Decode", func() { _ = a.Decode(p) })
			mustNotPanic(t, "AVP.String", func() { _ = a.String() })
			mustNotPanic(t, "AVP.StringWithPacket", func() { _ = a.StringWithPacket(p) })
			mustNotPanic(t, "DecodeAVPValue", func() {
				got := d.DecodeAVPValue(p, a)
				if tc.want != "" && got != tc.want {
					t.Errorf("DecodeAVPValue = %q, want %q", got, tc.want)
				}
			})
		})
	}
}

func TestMalformedPacketNoPanic(t *testing.T) {
	d := newMalformedTestDictionary(t)
	secret := "secret"
	req := Request(AccessRequest, secret)
	for _, tc := range malformedAVPs {
		req.AddAVP(tc.avp)
	}
	buf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}

	decoders := map[string]func() (*Packet, error){
		"DecodeRequest":       func() (*Packet, error) { return DecodeRequest(secret, buf) },
		"DecodeRequestLazy":   func() (*Packet, error) { return DecodeRequestLazy(secret, buf) },
		"DecodeRequestPooled": func() (*Packet, error) { return DecodeRequestPooled(secret, buf) },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			p, err := decode()
			if err != nil {
				t.Fatal(err)
			}
			mustNotPanic(t, "exercisePacket", func() { exercisePacket(p) })
			mustNotPanic(t, "Get* helpers", func() {
				if v := p.GetNASPort(); v != 0 {
					t.Errorf("GetNASPort = %d, want 0", v)
				}
				if v := p.GetAcctStatusType(); v != 0 {
					t.Errorf("GetAcctStatusType = %d, want 0", v)
				}
				_ = p.GetNASPortType()
				_ = p.GetServiceType()
				_, _ = p.GetVLAN()
			})
			mustNotPanic(t, "DecodeAVPValue", func() {
				p.EachAVP(func(a AVP) bool {
					_ = d.DecodeAVPValue(p, a)
					return true
				})
			})
		})
	}
}
