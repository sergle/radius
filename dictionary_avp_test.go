package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const newAVPTestDict = `
ATTRIBUTE	Test-Str	200	string
ATTRIBUTE	Test-Date	201	date
ATTRIBUTE	Test-Int	202	integer
VALUE		Test-Int	Test-Hex	0x01020304
VENDOR		NewAVPVendor	4242
BEGIN-VENDOR	NewAVPVendor
ATTRIBUTE	NewAVP-Str	1	string
ATTRIBUTE	NewAVP-Date	2	date
ATTRIBUTE	NewAVP-Int	3	integer
VALUE		NewAVP-Int	NewAVP-Seven	7
END-VENDOR	NewAVPVendor
`

const (
	newAVPTestAttr       AttributeType = 200
	newAVPTestVendor     VendorID      = 4242
	newAVPTestVendorAttr VendorAttr    = 1
	newAVPTestVendorInt  VendorAttr    = 3
	newAVPTestIntAttr    AttributeType = 202
)

func loadNewAVPTestDict(t *testing.T) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("newavp_test", strings.NewReader(newAVPTestDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

// noPanic runs f and fails the test if it panics.
func noPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	f()
}

func TestParseAVP(t *testing.T) {
	d := loadNewAVPTestDict(t)

	avp, err := d.ParseAVP("Test-Str", "hello")
	if err != nil {
		t.Fatalf("ParseAVP known: %v", err)
	}
	if avp.Type != newAVPTestAttr || !bytes.Equal(avp.Value, []byte("hello")) {
		t.Errorf("ParseAVP known = %+v", avp)
	}

	if _, err := d.ParseAVP("No-Such-Attr", "x"); !errors.Is(err, ErrUnknownAttribute) {
		t.Errorf("unknown attribute: err = %v, want ErrUnknownAttribute", err)
	}
	if _, err := d.ParseAVP("Test-Date", "x"); !errors.Is(err, ErrUnsupportedAttributeType) {
		t.Errorf("unsupported type: err = %v, want ErrUnsupportedAttributeType", err)
	}
}

func TestParseVSA(t *testing.T) {
	d := loadNewAVPTestDict(t)

	vsa, err := d.ParseVSA("NewAVPVendor", "NewAVP-Str", "hello")
	if err != nil {
		t.Fatalf("ParseVSA known: %v", err)
	}
	if vsa.Vendor != newAVPTestVendor || vsa.Type != newAVPTestVendorAttr || !bytes.Equal(vsa.Value, []byte("hello")) {
		t.Errorf("ParseVSA known = %+v", vsa)
	}

	if _, err := d.ParseVSA("No-Such-Vendor", "NewAVP-Str", "x"); !errors.Is(err, ErrUnknownVendor) {
		t.Errorf("unknown vendor: err = %v, want ErrUnknownVendor", err)
	}
	if _, err := d.ParseVSA("NewAVPVendor", "No-Such-Attr", "x"); !errors.Is(err, ErrUnknownAttribute) {
		t.Errorf("unknown VSA attribute: err = %v, want ErrUnknownAttribute", err)
	}
	if _, err := d.ParseVSA("NewAVPVendor", "NewAVP-Date", "x"); !errors.Is(err, ErrUnsupportedAttributeType) {
		t.Errorf("unsupported VSA type: err = %v, want ErrUnsupportedAttributeType", err)
	}
}

func TestNewAVPUnknown(t *testing.T) {
	d := loadNewAVPTestDict(t)

	if avp := d.NewAVP("Test-Str", "hello"); avp.Type != newAVPTestAttr || !bytes.Equal(avp.Value, []byte("hello")) {
		t.Errorf("NewAVP known = %+v", avp)
	}
	for _, name := range []string{"No-Such-Attr", "Test-Date"} {
		if avp := d.NewAVP(name, "x"); avp.Type != 0 || avp.Value != nil {
			t.Errorf("NewAVP(%q) = %+v, want zero AVP", name, avp)
		}
	}
}

func TestNewVSAUnknown(t *testing.T) {
	d := loadNewAVPTestDict(t)

	if vsa := d.NewVSA("NewAVPVendor", "NewAVP-Str", "hello"); vsa.Vendor != newAVPTestVendor || vsa.Type != newAVPTestVendorAttr {
		t.Errorf("NewVSA known = %+v", vsa)
	}
	cases := [][2]string{
		{"No-Such-Vendor", "NewAVP-Str"},
		{"NewAVPVendor", "No-Such-Attr"},
		{"NewAVPVendor", "NewAVP-Date"},
	}
	for _, c := range cases {
		noPanic(t, func() {
			if vsa := d.NewVSA(c[0], c[1], "x"); vsa.Vendor != 0 || vsa.Type != 0 || vsa.Value != nil {
				t.Errorf("NewVSA(%q, %q) = %+v, want zero VSA", c[0], c[1], vsa)
			}
		})
	}
}

func TestParseAVPValueName(t *testing.T) {
	d := GetDefaultDictionary()
	framed := []byte{0, 0, 0, byte(ServiceTypeEnumFramed)}

	avp, err := d.ParseAVP("Service-Type", "Framed")
	if err != nil {
		t.Fatalf("ParseAVP VALUE name: %v", err)
	}
	if avp.Type != AttrServiceType || !bytes.Equal(avp.Value, framed) {
		t.Errorf("ParseAVP VALUE name = %+v, want %v", avp, framed)
	}

	avp, err = d.ParseAVP("Service-Type", "2")
	if err != nil || !bytes.Equal(avp.Value, framed) {
		t.Errorf("ParseAVP number = %+v, %v; want %v", avp, err, framed)
	}

	for _, bad := range []string{"No-Such-Value", "garbage", "", "4294967296"} {
		if _, err := d.ParseAVP("Service-Type", bad); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseAVP(%q): err = %v, want ErrInvalidValue", bad, err)
		}
	}

	if avp := d.NewAVP("Service-Type", "Framed"); !bytes.Equal(avp.Value, framed) {
		t.Errorf("NewAVP VALUE name = %+v, want %v", avp, framed)
	}
	if avp := d.NewAVP("Service-Type", "garbage"); avp.Type != 0 || avp.Value != nil {
		t.Errorf("NewAVP garbage = %+v, want zero AVP", avp)
	}
}

func TestParseAVPHexValueName(t *testing.T) {
	d := loadNewAVPTestDict(t)
	avp, err := d.ParseAVP("Test-Int", "Test-Hex")
	if err != nil || avp.Type != newAVPTestIntAttr || !bytes.Equal(avp.Value, []byte{1, 2, 3, 4}) {
		t.Errorf("ParseAVP hex VALUE = %+v, %v", avp, err)
	}
}

func TestParseVSAValueName(t *testing.T) {
	d := loadNewAVPTestDict(t)
	seven := []byte{0, 0, 0, 7}

	vsa, err := d.ParseVSA("NewAVPVendor", "NewAVP-Int", "NewAVP-Seven")
	if err != nil {
		t.Fatalf("ParseVSA VALUE name: %v", err)
	}
	if vsa.Vendor != newAVPTestVendor || vsa.Type != newAVPTestVendorInt || !bytes.Equal(vsa.Value, seven) {
		t.Errorf("ParseVSA VALUE name = %+v, want %v", vsa, seven)
	}

	if vsa, err := d.ParseVSA("NewAVPVendor", "NewAVP-Int", "7"); err != nil || !bytes.Equal(vsa.Value, seven) {
		t.Errorf("ParseVSA number = %+v, %v; want %v", vsa, err, seven)
	}
	if _, err := d.ParseVSA("NewAVPVendor", "NewAVP-Int", "Framed"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseVSA other attr's VALUE: err = %v, want ErrInvalidValue", err)
	}
	if vsa := d.NewVSA("NewAVPVendor", "NewAVP-Int", "NewAVP-Seven"); !bytes.Equal(vsa.Value, seven) {
		t.Errorf("NewVSA VALUE name = %+v, want %v", vsa, seven)
	}
}
