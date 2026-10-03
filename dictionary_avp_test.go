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
VENDOR		NewAVPVendor	4242
BEGIN-VENDOR	NewAVPVendor
ATTRIBUTE	NewAVP-Str	1	string
ATTRIBUTE	NewAVP-Date	2	date
END-VENDOR	NewAVPVendor
`

const (
	newAVPTestAttr       AttributeType = 200
	newAVPTestVendor     VendorID      = 4242
	newAVPTestVendorAttr VendorAttr    = 1
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
