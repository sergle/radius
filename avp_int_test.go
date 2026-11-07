package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const sizedIntTestDict = `
ATTRIBUTE	Test-Byte	210	byte
VALUE		Test-Byte	Byte-One	1
ATTRIBUTE	Test-Short	211	short
VALUE		Test-Short	Short-Big	0x1234
ATTRIBUTE	Test-Signed	212	signed
VALUE		Test-Signed	Minus-One	-1
VENDOR		3GPP		10415
BEGIN-VENDOR	3GPP
ATTRIBUTE	3GPP-RAT-Type	21	byte
VALUE		3GPP-RAT-Type	UTRAN		1
VALUE		3GPP-RAT-Type	GERAN		2
VALUE		3GPP-RAT-Type	EUTRAN		6
END-VENDOR	3GPP
`

const (
	testByteAttr   AttributeType = 210
	testShortAttr  AttributeType = 211
	testSignedAttr AttributeType = 212
	ratTypeAttr    VendorAttr    = 21
	vendor3GPP     VendorID      = 10415
)

func loadSizedIntTestDict(t *testing.T) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("sizedint_test", strings.NewReader(sizedIntTestDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

// ratTypeAVP returns a 3GPP-RAT-Type VSA with the given raw value.
func ratTypeAVP(v ...byte) AVP {
	return VSA{Vendor: vendor3GPP, Type: ratTypeAttr, Value: v}.ToAVP()
}

func TestSizedIntDecodeAVPValue(t *testing.T) {
	d := loadSizedIntTestDict(t)
	tests := []struct {
		name string
		avp  AVP
		want string
	}{
		{"byte VALUE", AVP{testByteAttr, []byte{1}}, "Byte-One"},
		{"byte number", AVP{testByteAttr, []byte{200}}, "200"},
		{"byte too long", AVP{testByteAttr, []byte{0, 1}}, "[]byte{0x0, 0x1}"},
		{"byte empty", AVP{testByteAttr, []byte{}}, "[]byte{}"},
		{"short VALUE", AVP{testShortAttr, []byte{0x12, 0x34}}, "Short-Big"},
		{"short number", AVP{testShortAttr, []byte{0xff, 0xff}}, "65535"},
		{"short too short", AVP{testShortAttr, []byte{1}}, "[]byte{0x1}"},
		{"short too long", AVP{testShortAttr, []byte{0, 0, 0, 1}}, "[]byte{0x0, 0x0, 0x0, 0x1}"},
		{"signed negative", AVP{testSignedAttr, []byte{0xff, 0xff, 0xff, 0xfb}}, "-5"},
		{"signed positive", AVP{testSignedAttr, []byte{0, 0, 1, 0}}, "256"},
		{"signed VALUE", AVP{testSignedAttr, []byte{0xff, 0xff, 0xff, 0xff}}, "Minus-One"},
		{"signed too short", AVP{testSignedAttr, []byte{0, 0, 1}}, "[]byte{0x0, 0x0, 0x1}"},
		{"signed too long", AVP{testSignedAttr, []byte{0, 0, 0, 5, 0}}, "[]byte{0x0, 0x0, 0x0, 0x5, 0x0}"},
		{"VSA byte VALUE", ratTypeAVP(6), "{Vendor:3GPP #10415, Attr: 3GPP-RAT-Type #21, Value: EUTRAN}"},
		{"VSA byte number", ratTypeAVP(42), "{Vendor:3GPP #10415, Attr: 3GPP-RAT-Type #21, Value: 42}"},
		{"VSA byte too long", ratTypeAVP(0, 6), "{Vendor:3GPP #10415, Attr: 3GPP-RAT-Type #21, Value: []byte{0x0, 0x6}}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := d.DecodeAVPValue(nil, tc.avp); got != tc.want {
				t.Errorf("DecodeAVPValue = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSizedIntDecode(t *testing.T) {
	old := GetDefaultDictionary()
	SetDefaultDictionary(loadSizedIntTestDict(t))
	t.Cleanup(func() { SetDefaultDictionary(old) })

	tests := []struct {
		name string
		avp  AVP
		want any
	}{
		{"byte", AVP{testByteAttr, []byte{200}}, uint32(200)},
		{"short", AVP{testShortAttr, []byte{0x12, 0x34}}, uint32(0x1234)},
		{"signed", AVP{testSignedAttr, []byte{0xff, 0xff, 0xff, 0xfb}}, int32(-5)},
		{"byte too long", AVP{testByteAttr, []byte{0, 1}}, uint32(0)},
		{"short too short", AVP{testShortAttr, []byte{1}}, uint32(0)},
		{"signed too short", AVP{testSignedAttr, []byte{1}}, int32(0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.avp.Decode(nil); got != tc.want {
				t.Errorf("Decode = %#v, want %#v", got, tc.want)
			}
			if s := tc.avp.String(); strings.HasPrefix(s, "AVP type: Unknown") {
				t.Errorf("String = %q", s)
			}
		})
	}
}

func TestSizedIntParseAVP(t *testing.T) {
	d := loadSizedIntTestDict(t)
	tests := []struct {
		attr  string
		value string
		want  []byte // nil means ErrInvalidValue
	}{
		{"Test-Byte", "Byte-One", []byte{1}},
		{"Test-Byte", "255", []byte{255}},
		{"Test-Byte", "0x10", []byte{0x10}},
		{"Test-Byte", "256", nil},
		{"Test-Byte", "-1", nil},
		{"Test-Byte", "junk", nil},
		{"Test-Short", "Short-Big", []byte{0x12, 0x34}},
		{"Test-Short", "65535", []byte{0xff, 0xff}},
		{"Test-Short", "65536", nil},
		{"Test-Signed", "-5", []byte{0xff, 0xff, 0xff, 0xfb}},
		{"Test-Signed", "Minus-One", []byte{0xff, 0xff, 0xff, 0xff}},
		{"Test-Signed", "2147483647", []byte{0x7f, 0xff, 0xff, 0xff}},
		{"Test-Signed", "-2147483648", []byte{0x80, 0, 0, 0}},
		{"Test-Signed", "2147483648", nil},
		{"Test-Signed", "-2147483649", nil},
	}
	for _, tc := range tests {
		t.Run(tc.attr+"="+tc.value, func(t *testing.T) {
			avp, err := d.ParseAVP(tc.attr, tc.value)
			if tc.want == nil {
				if !errors.Is(err, ErrInvalidValue) {
					t.Errorf("err = %v, want ErrInvalidValue", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAVP: %v", err)
			}
			if !bytes.Equal(avp.Value, tc.want) {
				t.Errorf("value = %v, want %v", avp.Value, tc.want)
			}
		})
	}
}

func TestSizedIntParseVSA(t *testing.T) {
	d := loadSizedIntTestDict(t)
	for value, want := range map[string][]byte{"EUTRAN": {6}, "2": {2}, "255": {255}} {
		vsa, err := d.ParseVSA("3GPP", "3GPP-RAT-Type", value)
		if err != nil {
			t.Fatalf("ParseVSA %s: %v", value, err)
		}
		if vsa.Vendor != vendor3GPP || vsa.Type != ratTypeAttr || !bytes.Equal(vsa.Value, want) {
			t.Errorf("ParseVSA %s = %+v, want value %v", value, vsa, want)
		}
	}
	if _, err := d.ParseVSA("3GPP", "3GPP-RAT-Type", "256"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseVSA 256: err = %v, want ErrInvalidValue", err)
	}
}

func TestSizedIntTemplate(t *testing.T) {
	d := loadSizedIntTestDict(t)
	rt, err := d.CreateRequestTemplate(AccessRequest, "Test-Byte", "Test-Short", "Test-Signed")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.AddVSAAttribute(d, "3GPP", "3GPP-RAT-Type"); err != nil {
		t.Fatal(err)
	}

	p := &Packet{Code: AccessRequest}
	rt.Fill(p, "Byte-One", "4660", "-5", "EUTRAN")
	want := [][]byte{{1}, {0x12, 0x34}, {0xff, 0xff, 0xff, 0xfb}}
	if len(p.AVPs) != 4 {
		t.Fatalf("got %d AVPs, want 4: %+v", len(p.AVPs), p.AVPs)
	}
	for i, w := range want {
		if !bytes.Equal(p.AVPs[i].Value, w) {
			t.Errorf("AVP %d = %v, want %v", i, p.AVPs[i].Value, w)
		}
	}
	if vsa, ok := decodeVSA(p.AVPs[3], DefaultVendorFormat); !ok || !bytes.Equal(vsa.Value, []byte{6}) {
		t.Errorf("VSA = %+v, want value [6]", vsa)
	}

	// Out-of-range values are skipped.
	p = &Packet{Code: AccessRequest}
	rt.Fill(p, "256", "65536", "2147483648", "256")
	if len(p.AVPs) != 0 {
		t.Errorf("out-of-range values added AVPs: %+v", p.AVPs)
	}
}

func TestSizedIntNegativeValueOnlyForSigned(t *testing.T) {
	d := NewDictionary()
	err := d.loadReader("neg", strings.NewReader("ATTRIBUTE\tTest-Byte\t210\tbyte\nVALUE\tTest-Byte\tNeg\t-1\n"))
	if err == nil {
		t.Error("negative VALUE for byte attribute loaded without error")
	}
}

func TestSizedIntFromString(t *testing.T) {
	tests := []struct {
		handler avpDataType
		value   string
		want    []byte
	}{
		{avpUint8, "200", []byte{200}},
		{avpUint16, "0x1234", []byte{0x12, 0x34}},
		{avpInt32, "-5", []byte{0xff, 0xff, 0xff, 0xfb}},
	}
	for _, tc := range tests {
		got := tc.handler.FromString(tc.value)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%T.FromString(%q) = %v, want %v", tc.handler, tc.value, got, tc.want)
		}
		if s := tc.handler.String(nil, AVP{Value: got}); s == "invalid" {
			t.Errorf("%T.String(%v) = %q", tc.handler, got, s)
		}
	}
}
