package radius

import (
	"errors"
	"strings"
	"testing"
)

// freeradiusFlagsDict mimics FreeRADIUS dictionary lines with a flags column.
const freeradiusFlagsDict = `
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	User-Password		2	string	encrypt=1
ATTRIBUTE	Tunnel-Type		64	integer	has_tag
ATTRIBUTE	Tunnel-Password		69	string	has_tag,encrypt=2
ATTRIBUTE	Class			25	octets	concat
ATTRIBUTE	Unknown-Flagged		240	string	no-such-flag,array
ATTRIBUTE	Test-Secret		241	string	encrypt=1
VENDOR		Ascend		529
BEGIN-VENDOR	Ascend
ATTRIBUTE	Ascend-Send-Secret	214	string	encrypt=3
ATTRIBUTE	Ascend-Data-Filter	242	abinary
ATTRIBUTE	Ascend-Secret		215	string	encrypt=1
END-VENDOR	Ascend
`

// useFreeRADIUSFlagsDict swaps the default dictionary for the test's duration.
func useFreeRADIUSFlagsDict(t *testing.T) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("freeradius_flags", strings.NewReader(freeradiusFlagsDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	return d
}

func TestFreeRADIUSUserPasswordEncrypt1(t *testing.T) {
	d := useFreeRADIUSFlagsDict(t)
	const secret, password = "s3cr3t", "hunter2-correct-horse"

	req := Request(AccessRequest, secret)
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("bob")})
	req.AddPassword(password)
	buf, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	p, err := DecodeRequest(secret, buf)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}

	if got := p.GetPassword(); got != password {
		t.Errorf("GetPassword = %q, want %q", got, password)
	}
	avp := p.GetAVP(AttrUserPassword)
	if avp == nil {
		t.Fatal("User-Password missing")
	}
	if got := avp.Decode(p); got != password {
		t.Errorf("AVP.Decode = %#v, want %q", got, password)
	}
	if got := d.DecodeAVPValue(p, *avp); got != password {
		t.Errorf("DecodeAVPValue = %q, want %q", got, password)
	}
}

func TestFreeRADIUSVSAEncrypt1(t *testing.T) {
	d := useFreeRADIUSFlagsDict(t)
	if got := d.GetVSAAttributeType(d.GetVendorID("Ascend"), "Ascend-Secret"); got != "password" {
		t.Errorf("Ascend-Secret type = %q, want password", got)
	}
}

func TestFreeRADIUSOtherEncryptNotPlaintext(t *testing.T) {
	d := useFreeRADIUSFlagsDict(t)
	cipher := []byte{0x80, 0x01, 0xde, 0xad, 0xbe, 0xef}

	// encrypt=2 (Tunnel-Password) must not decode its ciphertext as a string.
	avp := AVP{Type: AttrTunnelPassword, Value: cipher}
	if _, ok := avp.Decode(nil).([]byte); !ok {
		t.Errorf("Tunnel-Password Decode = %#v, want []byte", avp.Decode(nil))
	}
	if got := d.DecodeAVPValue(nil, avp); got != avpBinary.String(nil, avp) {
		t.Errorf("Tunnel-Password DecodeAVPValue = %q, want binary form", got)
	}

	// encrypt=3 (Ascend-Send-Secret) likewise.
	if got := d.GetVSAAttributeType(d.GetVendorID("Ascend"), "Ascend-Send-Secret"); got != "octets" {
		t.Errorf("Ascend-Send-Secret type = %q, want octets", got)
	}
}

func TestFreeRADIUSFlagsParsed(t *testing.T) {
	d := useFreeRADIUSFlagsDict(t)

	cases := []struct {
		name, wantType string
		wantTag        bool
	}{
		{"User-Name", "string", false},
		{"User-Password", "password", false},
		{"Tunnel-Type", "integer", true},
		{"Tunnel-Password", "octets", true},
		{"Class", "octets", false},
		{"Unknown-Flagged", "string", false},
	}
	for _, c := range cases {
		if got := d.GetAttributeType(c.name); got != c.wantType {
			t.Errorf("%s type = %q, want %q", c.name, got, c.wantType)
		}
		if got := d.attrFlags[c.name].hasTag; got != c.wantTag {
			t.Errorf("%s hasTag = %v, want %v", c.name, got, c.wantTag)
		}
	}
	if !d.HasVSAAttribute(d.GetVendorID("Ascend"), "Ascend-Data-Filter") {
		t.Error("Ascend-Data-Filter not loaded")
	}
}

func TestBuiltinPasswordTypeUnchanged(t *testing.T) {
	d := NewDictionary()
	if err := d.LoadBuiltin(); err != nil {
		t.Fatal(err)
	}
	if got := d.GetAttributeType("User-Password"); got != "password" {
		t.Errorf("User-Password type = %q, want password", got)
	}
	if got := d.GetAttributeType("Tunnel-Password"); got != "octets" {
		t.Errorf("Tunnel-Password type = %q, want octets", got)
	}
}

// Encrypted attributes can't be built without a packet: they must not go out as plaintext.
func TestParseEncryptedAttributeFails(t *testing.T) {
	d := useFreeRADIUSFlagsDict(t)

	for _, name := range []string{"User-Password", "Test-Secret"} {
		if _, err := d.ParseAVP(name, "hunter2"); !errors.Is(err, ErrEncryptedAttribute) {
			t.Errorf("ParseAVP(%s): err = %v, want ErrEncryptedAttribute", name, err)
		}
		if avp := d.NewAVP(name, "hunter2"); avp.Type != 0 || avp.Value != nil {
			t.Errorf("NewAVP(%s) = %v, want zero AVP", name, avp)
		}
	}
	if _, err := d.ParseVSA("Ascend", "Ascend-Secret", "hunter2"); !errors.Is(err, ErrEncryptedAttribute) {
		t.Errorf("ParseVSA: err = %v, want ErrEncryptedAttribute", err)
	}
}

// Templates encrypt every encrypt=1 attribute, not only User-Password.
func TestTemplateEncryptsEncrypt1Attributes(t *testing.T) {
	const secret = "testing123"
	const plain = "hunter2-correct-horse"
	d := useFreeRADIUSFlagsDict(t)

	rt, err := d.CreateRequestTemplate(AccessRequest, "User-Password", "Test-Secret")
	if err != nil {
		t.Fatalf("CreateRequestTemplate: %v", err)
	}
	if err := rt.AddVSAAttribute(d, "Ascend", "Ascend-Secret"); err != nil {
		t.Fatalf("AddVSAAttribute: %v", err)
	}
	p := Request(AccessRequest, secret)
	rt.Fill(p, plain, plain, plain)

	values := map[string][]byte{}
	if a := p.GetAVP(AttrUserPassword); a != nil {
		values["User-Password"] = a.Value
	}
	if a := p.GetAVP(AttributeType(241)); a != nil {
		values["Test-Secret"] = a.Value
	}
	if a := p.GetAVP(AttrVendorSpecific); a != nil {
		values["Ascend-Secret"] = ToVSA(*a).Value
	}
	for _, name := range []string{"User-Password", "Test-Secret", "Ascend-Secret"} {
		v, ok := values[name]
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if string(v) == plain {
			t.Errorf("%s sent as plaintext", name)
		}
		if got := avpPassword.Value(p, AVP{Value: v}); got != plain {
			t.Errorf("%s decrypts to %q, want %q", name, got, plain)
		}
	}
}
