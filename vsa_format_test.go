package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

const (
	testLucentID  VendorID = 4846
	testStarentID VendorID = 8164
	testUSRID     VendorID = 429
	testWiMAXID   VendorID = 24757

	wimaxContinued    = 0x80 // continuation byte "more" flag
	wimaxFragmentData = maxAVPValueLen - vendorIDLen - 3
)

// vsaFormatDict declares vendors of each FreeRADIUS VENDOR format.
const vsaFormatDict = `
VENDOR		Lucent		4846	format=2,1
BEGIN-VENDOR	Lucent
ATTRIBUTE	Lucent-Max-Shared-Users	2	integer
ATTRIBUTE	Lucent-Retrain-Reason	20119	integer
VALUE	Lucent-Retrain-Reason	Line-Quality	1
END-VENDOR	Lucent

VENDOR		Starent		8164	format=2,2
BEGIN-VENDOR	Starent
ATTRIBUTE	SN-VPN-Name		2	string
ATTRIBUTE	SN-Big			300	ipaddr
END-VENDOR	Starent

VENDOR		USR		429	format=4,0
BEGIN-VENDOR	USR
ATTRIBUTE	USR-Channel		0xBF38	integer
ATTRIBUTE	USR-Huge		0x10000	string
END-VENDOR	USR

VENDOR		WiMAX		24757	format=1,1,c
BEGIN-VENDOR	WiMAX
ATTRIBUTE	WiMAX-Capability	1	tlv
ATTRIBUTE	WiMAX-Release		1.1	string
ATTRIBUTE	WiMAX-Hotline-Indicator	24	string
ATTRIBUTE	WiMAX-PDFID		26	short
VALUE	WiMAX-PDFID		Zero	0
END-VENDOR	WiMAX
`

func loadVSAFormatDict(t testing.TB) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("vsa_format_test", strings.NewReader(vsaFormatDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

func TestVendorFormatParse(t *testing.T) {
	d := loadVSAFormatDict(t)
	tests := []struct {
		vendor VendorID
		want   VendorFormat
	}{
		{testLucentID, VendorFormat{TypeLen: 2, LengthLen: 1}},
		{testStarentID, VendorFormat{TypeLen: 2, LengthLen: 2}},
		{testUSRID, VendorFormat{TypeLen: 4, LengthLen: 0}},
		{testWiMAXID, VendorFormat{TypeLen: 1, LengthLen: 1, Continuation: true}},
		{9, DefaultVendorFormat},
	}
	for _, tt := range tests {
		if got := d.VendorFormat(tt.vendor); got != tt.want {
			t.Errorf("VendorFormat(%d) = %+v, want %+v", tt.vendor, got, tt.want)
		}
	}
	// attribute numbers wider than one byte
	if id := d.GetVSAAttributeID(testLucentID, "Lucent-Retrain-Reason"); id != 20119 {
		t.Errorf("Lucent-Retrain-Reason id = %d", id)
	}
	if id := d.GetVSAAttributeID(testUSRID, "USR-Huge"); id != 0x10000 {
		t.Errorf("USR-Huge id = %d", id)
	}
}

func TestVendorFormatInvalid(t *testing.T) {
	for _, format := range []string{"format=3,1", "format=1,3", "format=2,1,c", "format=1,1,x", "format=1", "format=a,b", "format=1,1,c,c"} {
		d := NewDictionary()
		if err := d.loadReader("bad", strings.NewReader("VENDOR V 9 "+format)); err == nil {
			t.Errorf("%s: expected error", format)
		}
	}
}

// Attribute numbers must fit the vendor's type size.
func TestVendorFormatAttrIDRange(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, `
VENDOR L 9 format=2,1
VENDOR P 10
BEGIN-VENDOR L
ATTRIBUTE L-Big 65536 integer
END-VENDOR L
BEGIN-VENDOR P
ATTRIBUTE P-Big 256 integer
END-VENDOR P
`)
	if d.HasVSAAttribute(9, "L-Big") || d.HasVSAAttribute(10, "P-Big") {
		t.Error("out-of-range attribute loaded")
	}
	if n := strings.Count(h.all(), "invalid id"); n != 2 {
		t.Errorf("invalid id warnings = %d, want 2:\n%s", n, h.all())
	}
}

func TestVSAFormatEncode(t *testing.T) {
	d := loadVSAFormatDict(t)
	tests := []struct {
		vendor, attr, value string
		want                []byte
	}{
		{"Lucent", "Lucent-Retrain-Reason", "Line-Quality",
			[]byte{0, 0, 0x12, 0xee, 0x4e, 0x97, 7, 0, 0, 0, 1}},
		{"Starent", "SN-VPN-Name", "ab",
			[]byte{0, 0, 0x1f, 0xe4, 0, 2, 0, 6, 'a', 'b'}},
		{"USR", "USR-Channel", "5",
			[]byte{0, 0, 1, 0xad, 0, 0, 0xbf, 0x38, 0, 0, 0, 5}},
		{"WiMAX", "WiMAX-PDFID", "Zero",
			[]byte{0, 0, 0x60, 0xb5, 26, 5, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			vsa, err := d.ParseVSA(tt.vendor, tt.attr, tt.value)
			if err != nil {
				t.Fatal(err)
			}
			p := Request(AccessRequest, "secret")
			p.AddVSA(vsa)
			if len(p.AVPs) != 1 || !bytes.Equal(p.AVPs[0].Value, tt.want) {
				t.Fatalf("AVPs = %v, want %v", p.AVPs, tt.want)
			}
			// templates encode the same way
			tmpl := &RequestTemplate{code: AccessRequest}
			if err := tmpl.AddVSAAttribute(d, tt.vendor, tt.attr); err != nil {
				t.Fatal(err)
			}
			p = Request(AccessRequest, "secret")
			tmpl.Fill(p, tt.value)
			if len(p.AVPs) != 1 || !bytes.Equal(p.AVPs[0].Value, tt.want) {
				t.Errorf("template AVPs = %v, want %v", p.AVPs, tt.want)
			}
		})
	}
}

func TestVSAFormatDecode(t *testing.T) {
	d := loadVSAFormatDict(t)
	tests := []struct {
		name string
		avp  AVP
		want string
	}{
		{"2,1", VSA{Vendor: testLucentID, Type: 20119, Value: []byte{0, 0, 0, 1}, Format: d.VendorFormat(testLucentID)}.ToAVP(),
			"{Vendor:Lucent #4846, Attr: Lucent-Retrain-Reason #20119, Value: Line-Quality}"},
		{"2,2", VSA{Vendor: testStarentID, Type: 300, Value: []byte{10, 0, 0, 1}, Format: d.VendorFormat(testStarentID)}.ToAVP(),
			"{Vendor:Starent #8164, Attr: SN-Big #300, Value: 10.0.0.1}"},
		{"4,0", VSA{Vendor: testUSRID, Type: 0xBF38, Value: []byte{0, 0, 0, 5}, Format: d.VendorFormat(testUSRID)}.ToAVP(),
			"{Vendor:USR #429, Attr: USR-Channel #48952, Value: 5}"},
		{"1,1,c", AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x60, 0xb5, 26, 5, 0, 0, 0}},
			"{Vendor:WiMAX #24757, Attr: WiMAX-PDFID #26, Value: Zero}"},
		{"1,1,c tlv", AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x60, 0xb5, 1, 8, 0, 1, 5, '2', '.', '1'}},
			"{Vendor:WiMAX #24757, Attr: WiMAX-Capability #1, Value: {WiMAX-Release: 2.1}}"},
		{"2,1 short", AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x12, 0xee, 0x4e, 0x97}},
			""},
		{"2,2 bad length", AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x1f, 0xe4, 0, 2, 0, 9, 'a'}},
			""},
		{"1,1,c no continuation byte", AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x60, 0xb5, 24, 2}},
			""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				// malformed values render as octets
				want = avpBinary.String(nil, tt.avp)
			}
			if got := d.DecodeAVPValue(nil, tt.avp); got != want {
				t.Errorf("DecodeAVPValue =\n %q\nwant\n %q", got, want)
			}
		})
	}
}

// ToVSA uses the default dictionary's vendor format.
func TestToVSAFormat(t *testing.T) {
	d := loadVSAFormatDict(t)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	defer SetDefaultDictionary(old)

	vsa := ToVSA(AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x12, 0xee, 0x4e, 0x97, 7, 0, 0, 0, 1}})
	if vsa.Vendor != testLucentID || vsa.Type != 20119 || !bytes.Equal(vsa.Value, []byte{0, 0, 0, 1}) {
		t.Errorf("ToVSA = %+v", vsa)
	}
	if vsa.Format != d.VendorFormat(testLucentID) {
		t.Errorf("ToVSA format = %+v", vsa.Format)
	}
}

// A zero Format encodes as format=1,1.
func TestVSAZeroFormat(t *testing.T) {
	avp := VSA{Vendor: 9, Type: 1, Value: []byte{'x'}}.ToAVP()
	if want := []byte{0, 0, 0, 9, 1, 3, 'x'}; !bytes.Equal(avp.Value, want) {
		t.Errorf("ToAVP = %v, want %v", avp.Value, want)
	}
}

// Long WiMAX values are split over several AVPs with the continuation flag.
func TestWiMAXContinuationEncode(t *testing.T) {
	d := loadVSAFormatDict(t)
	long := bytes.Repeat([]byte{'a'}, wimaxFragmentData*2+10)
	vsa, err := d.ParseVSA("WiMAX", "WiMAX-Hotline-Indicator", string(long))
	if err != nil {
		t.Fatal(err)
	}
	avps := vsa.ToAVPList()
	if len(avps) != 3 {
		t.Fatalf("AVPs = %d, want 3", len(avps))
	}
	var joined []byte
	for i, a := range avps {
		if a.Type != AttrVendorSpecific || len(a.Value) > maxAVPValueLen {
			t.Fatalf("AVP %d: type %d, len %d", i, a.Type, len(a.Value))
		}
		v := a.Value[vendorIDLen:]
		if v[0] != 24 || int(v[1]) != len(v) {
			t.Errorf("AVP %d header = %v", i, v[:3])
		}
		if more := v[2]&wimaxContinued != 0; more != (i < len(avps)-1) {
			t.Errorf("AVP %d continuation = %v", i, more)
		}
		joined = append(joined, v[3:]...)
	}
	if !bytes.Equal(joined, long) {
		t.Error("fragments don't reassemble the value")
	}

	// round trip through a packet
	p := Request(AccessRequest, "secret")
	p.AddVSA(vsa)
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, decode := range []func(string, []byte) (*Packet, error){DecodeRequest, DecodeRequestLazy} {
		q, err := decode("secret", buf)
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := d.GetVSA(q, "WiMAX", "WiMAX-Hotline-Indicator"); !ok || !bytes.Equal(v, long) {
			t.Errorf("GetVSA = %d bytes, %v", len(v), ok)
		}
	}
}

func TestGetVSA(t *testing.T) {
	d := loadVSAFormatDict(t)
	frag := func(typ uint8, more bool, v string) AVP {
		flag := byte(0)
		if more {
			flag = wimaxContinued
		}
		return AVP{Type: AttrVendorSpecific, Value: append([]byte{0, 0, 0x60, 0xb5, typ, byte(3 + len(v)), flag}, v...)}
	}
	p := Request(AccessRequest, "secret")
	p.AddAVP(
		// two Lucent attributes in one Vendor-Specific
		AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x12, 0xee, 0, 2, 7, 0, 0, 0, 3, 0x4e, 0x97, 7, 0, 0, 0, 1}},
		frag(26, false, "\x00\x07"),
		frag(24, true, "ab"),
		frag(24, true, "cd"),
		frag(24, false, "e"),
		// a TLV split over two fragments
		frag(1, true, "\x01\x05"),
		frag(1, false, "2.1"),
	)
	tests := []struct {
		vendor, attr string
		want         string
	}{
		{"Lucent", "Lucent-Max-Shared-Users", "\x00\x00\x00\x03"},
		{"Lucent", "Lucent-Retrain-Reason", "\x00\x00\x00\x01"},
		{"WiMAX", "WiMAX-PDFID", "\x00\x07"},
		{"WiMAX", "WiMAX-Hotline-Indicator", "abcde"},
		{"WiMAX", "WiMAX-Capability", "\x01\x052.1"},
	}
	for _, tt := range tests {
		if v, ok := d.GetVSA(p, tt.vendor, tt.attr); !ok || string(v) != tt.want {
			t.Errorf("GetVSA %s = %q, %v; want %q", tt.attr, v, ok, tt.want)
		}
	}
	if v, ok := d.GetTLV(p, "WiMAX", "WiMAX-Release"); !ok || string(v) != "2.1" {
		t.Errorf("GetTLV WiMAX-Release = %q, %v", v, ok)
	}
	for _, c := range [][2]string{{"Lucent", "Nope"}, {"Nope", "X"}, {"Starent", "SN-VPN-Name"}} {
		if _, ok := d.GetVSA(p, c[0], c[1]); ok {
			t.Errorf("GetVSA %s/%s found", c[0], c[1])
		}
	}
}

// An interrupted or unterminated continuation yields the fragments seen so far.
func TestGetVSAContinuationInterrupted(t *testing.T) {
	d := loadVSAFormatDict(t)
	p := Request(AccessRequest, "secret")
	p.AddAVP(
		AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x60, 0xb5, 24, 5, wimaxContinued, 'a', 'b'}},
		AVP{Type: AttrUserName, Value: []byte("u")},
		AVP{Type: AttrVendorSpecific, Value: []byte{0, 0, 0x60, 0xb5, 26, 5, wimaxContinued, 0, 1}},
	)
	if v, ok := d.GetVSA(p, "WiMAX", "WiMAX-Hotline-Indicator"); !ok || string(v) != "ab" {
		t.Errorf("GetVSA interrupted = %q, %v", v, ok)
	}
	if v, ok := d.GetVSA(p, "WiMAX", "WiMAX-PDFID"); !ok || !bytes.Equal(v, []byte{0, 1}) {
		t.Errorf("GetVSA unterminated = %v, %v", v, ok)
	}
}

// WiMAX TLVs are built with the continuation byte.
func TestWiMAXParseTLV(t *testing.T) {
	d := loadVSAFormatDict(t)
	avp, err := buildTLV(d, "WiMAX", "WiMAX-Capability", tlvValue{Name: "WiMAX-Release", Value: "2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0, 0x60, 0xb5, 1, 8, 0, 1, 5, '2', '.', '1'}; !bytes.Equal(avp.Value, want) {
		t.Errorf("ParseTLV = %v, want %v", avp.Value, want)
	}
	if _, err := buildTLV(d, "WiMAX", "WiMAX-Capability", tlvValue{Name: "WiMAX-Release", Value: strings.Repeat("a", wimaxFragmentData-tlvHeaderLen+1)}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("too long: err = %v", err)
	}
}

// Lucent, Starent and USR dictionaries are no longer skipped.
func TestWideVendorDictionariesIncluded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/dictionary", "$INCLUDE dictionary.lucent\n$INCLUDE dictionary.starent\n$INCLUDE dictionary.usr\n")
	writeFile(t, dir+"/dictionary.lucent", "VENDOR Lucent 4846 format=2,1\nBEGIN-VENDOR Lucent\nATTRIBUTE Lucent-X 20119 integer\nEND-VENDOR Lucent\n")
	writeFile(t, dir+"/dictionary.starent", "VENDOR Starent 8164 format=2,2\nBEGIN-VENDOR Starent\nATTRIBUTE SN-X 300 integer\nEND-VENDOR Starent\n")
	writeFile(t, dir+"/dictionary.usr", "VENDOR USR 429 format=4,0\nBEGIN-VENDOR USR\nATTRIBUTE USR-X 0xBF38 integer\nEND-VENDOR USR\n")
	d := NewDictionary()
	if err := d.LoadFile(dir + "/dictionary"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		vendor VendorID
		attr   string
	}{{testLucentID, "Lucent-X"}, {testStarentID, "SN-X"}, {testUSRID, "USR-X"}} {
		if !d.HasVSAAttribute(c.vendor, c.attr) {
			t.Errorf("%s not loaded", c.attr)
		}
	}
}

func FuzzVSAFormatDecode(f *testing.F) {
	d := loadVSAFormatDict(f)
	f.Add([]byte{0, 2, 7, 0, 0, 0, 3, 0x4e, 0x97, 7, 0, 0, 0, 1})
	f.Add([]byte{1, 7, wimaxContinued, 1, 4, '2', '.'})
	f.Add([]byte{0, 0, 0xbf, 0x38, 0, 0, 0, 5})
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > maxAVPValueLen-vendorIDLen {
			return
		}
		p := Request(AccessRequest, "secret")
		for _, vendor := range []VendorID{testLucentID, testStarentID, testUSRID, testWiMAXID} {
			a := AVP{Type: AttrVendorSpecific, Value: binary.BigEndian.AppendUint32(nil, uint32(vendor))}
			a.Value = append(a.Value, value...)
			p.AddAVP(a, a)
			_ = d.DecodeAVPValue(p, a)
		}
		for _, c := range [][2]string{{"Lucent", "Lucent-Retrain-Reason"}, {"Starent", "SN-Big"}, {"USR", "USR-Channel"}, {"WiMAX", "WiMAX-Hotline-Indicator"}} {
			d.GetVSA(p, c[0], c[1])
		}
		d.GetTLV(p, "WiMAX", "WiMAX-Release")
	})
}

// A VSA whose format is invalid or too small for its type isn't encoded.
func TestVSAEncodeInvalid(t *testing.T) {
	h := useRecordLogger(t)
	tests := []struct {
		name string
		vsa  VSA
	}{
		{"type too big for 1,1", VSA{Vendor: testLucentID, Type: 20119, Value: []byte{1}}},
		{"type too big for 2,1", VSA{Vendor: testLucentID, Type: 0x10000, Value: []byte{1}, Format: VendorFormat{TypeLen: 2, LengthLen: 1}}},
		{"continuation only", VSA{Vendor: 9, Type: 1, Value: []byte{1}, Format: VendorFormat{Continuation: true}}},
		{"type size 3", VSA{Vendor: 9, Type: 1, Value: []byte{1}, Format: VendorFormat{TypeLen: 3, LengthLen: 1}}},
		{"length size 3", VSA{Vendor: 9, Type: 1, Value: []byte{1}, Format: VendorFormat{TypeLen: 1, LengthLen: 3}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if avp := tt.vsa.ToAVP(); avp.Type != 0 || avp.Value != nil {
				t.Errorf("ToAVP = %v, want zero AVP", avp)
			}
			if avps := tt.vsa.ToAVPList(); avps != nil {
				t.Errorf("ToAVPList = %v, want nil", avps)
			}
			p := Request(AccessRequest, "secret")
			p.AddVSA(tt.vsa)
			if len(p.AVPs) != 0 {
				t.Errorf("AddVSA added %v", p.AVPs)
			}
		})
	}
	if !strings.Contains(h.all(), "invalid vendor format") {
		t.Errorf("no warning:\n%s", h.all())
	}
	for _, f := range []VendorFormat{{}, DefaultVendorFormat, {TypeLen: 1, LengthLen: 1, Continuation: true}, {TypeLen: 2, LengthLen: 2}, {TypeLen: 4}, {TypeLen: 1, LengthLen: 0}} {
		if !f.Valid() {
			t.Errorf("%+v: not valid", f)
		}
	}
}

// ParseVSA and templates refuse a number that doesn't fit the vendor's current format.
func TestVSATypeTooBigAfterFormatChange(t *testing.T) {
	d := loadTLVDict(t, `
VENDOR S 8164 format=2,2
BEGIN-VENDOR S
ATTRIBUTE S-Big 300 integer
END-VENDOR S
VENDOR S 8164 format=1,1
`)
	if _, err := d.ParseVSA("S", "S-Big", "5"); !errors.Is(err, ErrInvalidVendorFormat) {
		t.Errorf("ParseVSA: err = %v", err)
	}
	var rt RequestTemplate
	if err := rt.AddVSAAttribute(d, "S", "S-Big"); !errors.Is(err, ErrInvalidVendorFormat) {
		t.Errorf("template: err = %v", err)
	}
}

// format= is required and the only accepted VENDOR option.
func TestVendorFormatPrefix(t *testing.T) {
	if err := NewDictionary().loadReader("bad", strings.NewReader("VENDOR V 9 1,1")); err == nil {
		t.Error("format without format=: expected error")
	}
	for _, format := range []string{"format=1,2", "format=1,0", "format=2,0", "format=4,2"} {
		if err := NewDictionary().loadReader("ok", strings.NewReader("VENDOR V 9 "+format)); err != nil {
			t.Errorf("%s: %v", format, err)
		}
	}
	if err := NewDictionary().loadReader("bad", strings.NewReader("VENDOR V 9 format=4,0,c")); err == nil {
		t.Error("format=4,0,c: expected error")
	}
}
