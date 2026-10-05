package radius

import (
	"strings"
	"testing"
)

// freeradiusV4Dict uses FreeRADIUS v4 type names and encrypt spellings.
const freeradiusV4Dict = `
ATTRIBUTE	User-Password		2	string	encrypt=User-Password
ATTRIBUTE	NAS-IP-Address		4	ipv4addr
ATTRIBUTE	Session-Timeout		27	uint32
ATTRIBUTE	Termination-Action	29	uint32
VALUE	Termination-Action	Default			0
VALUE	Termination-Action	RADIUS-Request		1
ATTRIBUTE	Tunnel-Type		64	uint32	has_tag
ATTRIBUTE	Tunnel-Password		69	string	has_tag,encrypt=Tunnel-Password
ATTRIBUTE	Test-Uint8		240	uint8
ATTRIBUTE	Test-Uint16		241	uint16
ATTRIBUTE	Test-Int32		242	int32
ATTRIBUTE	Test-Uint64		243	uint64
VENDOR		Ascend		529
BEGIN-VENDOR	Ascend
ATTRIBUTE	Send-Secret		214	string	encrypt=Ascend-Secret
ATTRIBUTE	Data-Rate		197	uint32
END-VENDOR	Ascend
`

func TestFreeRADIUSV4Types(t *testing.T) {
	d := NewDictionary()
	if err := d.loadReader("freeradius_v4", strings.NewReader(freeradiusV4Dict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}

	cases := []struct{ name, wantType string }{
		{"User-Password", "password"},
		{"NAS-IP-Address", "ipaddr"},
		{"Session-Timeout", "integer"},
		{"Termination-Action", "integer"},
		{"Tunnel-Type", "tagged-integer"},
		{"Tunnel-Password", "tunnel-password"},
		{"Test-Uint8", "byte"},
		{"Test-Uint16", "short"},
		{"Test-Int32", "signed"},
		{"Test-Uint64", "integer64"},
	}
	for _, c := range cases {
		if got := d.GetAttributeType(c.name); got != c.wantType {
			t.Errorf("%s type = %q, want %q", c.name, got, c.wantType)
		}
	}
	ascend := d.GetVendorID("Ascend")
	if got := d.GetVSAAttributeType(ascend, "Data-Rate"); got != "integer" {
		t.Errorf("Data-Rate type = %q, want integer", got)
	}
	if got := d.GetVSAAttributeType(ascend, "Send-Secret"); got != "octets" {
		t.Errorf("Send-Secret type = %q, want octets", got)
	}

	avp := AVP{Type: AttrTerminationAction, Value: []byte{0, 0, 0, 1}}
	if got := d.DecodeAVPValue(nil, avp); got != "RADIUS-Request" {
		t.Errorf("Termination-Action = %q, want RADIUS-Request", got)
	}
	avp = AVP{Type: AttrSessionTimeout, Value: []byte{0, 0, 0x0e, 0x10}}
	if got := d.DecodeAVPValue(nil, avp); got != "3600" {
		t.Errorf("Session-Timeout = %q, want 3600", got)
	}

	// sized integers decode through the byte/short/signed handlers
	for _, c := range []struct {
		t     AttributeType
		value []byte
		want  string
	}{
		{240, []byte{7}, "7"},
		{241, []byte{1, 0}, "256"},
		{242, []byte{0xff, 0xff, 0xff, 0xfb}, "-5"},
	} {
		if got := d.DecodeAVPValue(nil, AVP{Type: c.t, Value: c.value}); got != c.want {
			t.Errorf("attr %d = %q, want %q", c.t, got, c.want)
		}
	}
}
