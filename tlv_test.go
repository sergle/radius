package radius

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

const testTLVVendorID = 9998

// tlvTestDict declares TLVs with dotted OIDs (as FreeRADIUS v3.2) and with BEGIN-TLV blocks.
const tlvTestDict = `
VENDOR		TLVVendor	9998
BEGIN-VENDOR	TLVVendor
ATTRIBUTE	TLV-Plain		1	integer
ATTRIBUTE	TLV-Remote		2	tlv
ATTRIBUTE	TLV-Remote-Addr		2.1	ipaddr
ATTRIBUTE	TLV-Remote-Mask		2.2	integer
ATTRIBUTE	TLV-Remote-Qualifier	2.3	short
VALUE	TLV-Remote-Qualifier	Exact	1
ATTRIBUTE	TLV-Remote-Nested	2.4	tlv
ATTRIBUTE	TLV-Remote-Nested-Name	2.4.1	string
ATTRIBUTE	TLV-Remote-Nested-Count	2.4.2	byte
ATTRIBUTE	TLV-Block		3	tlv
BEGIN-TLV	TLV-Block
ATTRIBUTE	TLV-Block-Id		1	integer
VALUE	TLV-Block-Id		First	1
ATTRIBUTE	TLV-Block-Inner		2	tlv
BEGIN-TLV	TLV-Block-Inner
ATTRIBUTE	TLV-Block-Inner-Name	1	string
END-TLV		TLV-Block-Inner
END-TLV		TLV-Block
ATTRIBUTE	TLV-After		4	string
END-VENDOR	TLVVendor

ATTRIBUTE	Test-Std-TLV		173	tlv
ATTRIBUTE	Test-Std-TLV-Len	173.1	integer
ATTRIBUTE	Test-Std-TLV-Addr	173.3	ipaddr

VENDOR		TLVWide		9997	format=2,1
BEGIN-VENDOR	TLVWide
ATTRIBUTE	TW-Capability		1	tlv
ATTRIBUTE	TW-Release		1.1	string
ATTRIBUTE	TW-Flow			2	tlv
BEGIN-TLV	TW-Flow
ATTRIBUTE	TW-Flow-Id		1	short
VALUE	TW-Flow-Id		Zero	0
END-TLV		TW-Flow
END-VENDOR	TLVWide

ATTRIBUTE	Test-Extended		241	extended
ATTRIBUTE	Test-Ext-Len		241.3	integer
VALUE	Test-Ext-Len		One	1
`

func loadTLVTestDict(t testing.TB) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("tlv_test", strings.NewReader(tlvTestDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

// vsaAVP wraps a raw VSA value of the test vendor.
func vsaAVP(vendor VendorID, attr VendorAttr, value []byte) AVP {
	return VSA{Vendor: vendor, Type: attr, Value: value}.ToAVP()
}

// remoteValue is TLV-Remote with Addr, Qualifier, Nested{Name, Count} and an unknown child #9.
var remoteValue = []byte{
	1, 6, 10, 0, 0, 1,
	3, 4, 0, 1,
	4, 10, 1, 5, 'a', 'b', 'c', 2, 3, 7,
	9, 3, 0xff,
}

func TestTLVDictionaryParse(t *testing.T) {
	d := loadTLVTestDict(t)
	v := d.GetVendorID("TLVVendor")
	if got := d.GetVSAAttributeType(v, "TLV-Remote"); got != "tlv" {
		t.Errorf("TLV-Remote type = %q, want tlv", got)
	}
	// children are not top-level VSAs
	if d.HasVSAAttribute(v, "TLV-Remote-Addr") || d.HasVSAAttribute(v, "TLV-Block-Id") {
		t.Error("TLV children registered as top-level VSAs")
	}
	// BEGIN-TLV state is closed: following attribute is top-level
	if id := d.GetVSAAttributeID(v, "TLV-After"); id != 4 {
		t.Errorf("TLV-After id = %d, want 4", id)
	}
	if got := d.GetAttributeType("Test-Std-TLV"); got != "tlv" {
		t.Errorf("Test-Std-TLV type = %q, want tlv", got)
	}
	// unsupported vendor format still loads as top-level
	if !d.HasVSAAttribute(d.GetVendorID("TLVWide"), "TW-Capability") {
		t.Error("TW-Capability missing")
	}
	// extended attributes aren't top-level
	if !d.HasAttribute("Test-Extended") || d.HasAttribute("Test-Ext-Len") {
		t.Error("extended attribute handling changed")
	}
	if _, err := d.ParseExtended("", "Test-Ext-Len", "One"); err != nil {
		t.Errorf("Test-Ext-Len: %v", err)
	}
}

func TestTLVDictionaryErrors(t *testing.T) {
	tests := []struct{ name, dict string }{
		{"BEGIN-TLV unknown", "BEGIN-TLV Nope"},
		{"END-TLV unknown", "END-TLV Nope"},
		{"END-TLV without BEGIN", "ATTRIBUTE A 1 tlv\nEND-TLV A"},
		{"END-TLV mismatch", "ATTRIBUTE A 1 tlv\nATTRIBUTE B 2 tlv\nBEGIN-TLV A\nEND-TLV B"},
		{"BEGIN-TLV not a tlv", "ATTRIBUTE A 1 integer\nBEGIN-TLV A"},
		{"BEGIN-TLV leaf child", "ATTRIBUTE A 1 tlv\nATTRIBUTE B 1.1 integer\nBEGIN-TLV B"},
		{"bad VALUE of child", "ATTRIBUTE A 1 tlv\nATTRIBUTE B 1.1 integer\nVALUE B X nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDictionary()
			if err := d.loadReader("bad", strings.NewReader(tt.dict)); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestTLVDecodeVSA(t *testing.T) {
	d := loadTLVTestDict(t)
	tests := []struct {
		name string
		avp  AVP
		want string
	}{
		{"dotted with nested and unknown child", vsaAVP(testTLVVendorID, 2, remoteValue),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: {TLV-Remote-Addr: 10.0.0.1, TLV-Remote-Qualifier: Exact, " +
				"TLV-Remote-Nested: {TLV-Remote-Nested-Name: abc, TLV-Remote-Nested-Count: 7}, #9: []byte{0xff}}}"},
		{"BEGIN-TLV nested", vsaAVP(testTLVVendorID, 3, []byte{1, 6, 0, 0, 0, 1, 2, 5, 1, 3, 'x', 1, 6, 0, 0, 0, 2}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Block #3, Value: {TLV-Block-Id: First, TLV-Block-Inner: {TLV-Block-Inner-Name: x}, TLV-Block-Id: 2}}"},
		{"short child value", vsaAVP(testTLVVendorID, 2, []byte{2, 3, 1}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: {TLV-Remote-Mask: []byte{0x1}}}"},
		{"bad child length", vsaAVP(testTLVVendorID, 2, []byte{1, 1, 10}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: []byte{0x1, 0x1, 0xa}}"},
		{"child overruns", vsaAVP(testTLVVendorID, 2, []byte{1, 6, 10, 0}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: []byte{0x1, 0x6, 0xa, 0x0}}"},
		{"truncated header", vsaAVP(testTLVVendorID, 2, []byte{1, 6, 10, 0, 0, 1, 3}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: []byte{0x1, 0x6, 0xa, 0x0, 0x0, 0x1, 0x3}}"},
		{"empty", vsaAVP(testTLVVendorID, 2, []byte{}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: []byte{}}"},
		{"malformed nested", vsaAVP(testTLVVendorID, 2, []byte{4, 4, 1, 9}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: {TLV-Remote-Nested: []byte{0x1, 0x9}}}"},
		{"unsupported vendor format", VSA{Vendor: 9997, Type: 1, Value: []byte{1, 3, 'a'}, Format: VendorFormat{TypeLen: 2, LengthLen: 1}}.ToAVP(),
			"{Vendor:TLVWide #9997, Attr: TW-Capability #1, Value: []byte{0x1, 0x3, 0x61}}"},
		{"non-TLV unchanged", vsaAVP(testTLVVendorID, 1, []byte{0, 0, 0, 5}),
			"{Vendor:TLVVendor #9998, Attr: TLV-Plain #1, Value: 5}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.DecodeAVPValue(nil, tt.avp); got != tt.want {
				t.Errorf("DecodeAVPValue =\n %q\nwant\n %q", got, tt.want)
			}
		})
	}
}

func TestTLVDecodeStandard(t *testing.T) {
	d := loadTLVTestDict(t)
	avp := AVP{Type: 173, Value: []byte{1, 6, 0, 0, 0, 24, 3, 6, 192, 0, 2, 1}}
	want := "{Test-Std-TLV-Len: 24, Test-Std-TLV-Addr: 192.0.2.1}"
	if got := d.DecodeAVPValue(nil, avp); got != want {
		t.Errorf("DecodeAVPValue = %q, want %q", got, want)
	}

	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	if got := avp.String(); got != "AVP type: Test-Std-TLV "+want {
		t.Errorf("AVP.String = %q", got)
	}
	if got, ok := avp.Decode(nil).([]byte); !ok || !bytes.Equal(got, avp.Value) {
		t.Errorf("AVP.Decode = %#v, want raw bytes", avp.Decode(nil))
	}
	bad := AVP{Type: 173, Value: []byte{1, 9}}
	if got := bad.String(); got != "AVP type: Test-Std-TLV []byte{0x1, 0x9}" {
		t.Errorf("malformed AVP.String = %q", got)
	}
}

func TestParseTLV(t *testing.T) {
	d := loadTLVTestDict(t)

	avp, err := d.ParseTLV("TLVVendor", "TLV-Remote",
		TLVValue{Name: "TLV-Remote-Addr", Value: "10.0.0.1"},
		TLVValue{Name: "TLV-Remote-Qualifier", Value: "Exact"},
		TLVValue{Name: "TLV-Remote-Nested-Name", Value: "abc"},
		TLVValue{Name: "TLV-Remote-Nested-Count", Value: "7"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := vsaAVP(testTLVVendorID, 2, remoteValue[:len(remoteValue)-3])
	if avp.Type != want.Type || !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("ParseTLV = %#v, want %#v", avp, want)
	}

	// non-consecutive children of a nested TLV go into separate instances
	avp, err = d.ParseTLV("TLVVendor", "TLV-Remote",
		TLVValue{Name: "TLV-Remote-Nested-Name", Value: "a"},
		TLVValue{Name: "TLV-Remote-Mask", Value: "24"},
		TLVValue{Name: "TLV-Remote-Nested-Count", Value: "1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want = vsaAVP(testTLVVendorID, 2, []byte{4, 5, 1, 3, 'a', 2, 6, 0, 0, 0, 24, 4, 5, 2, 3, 1})
	if !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("ParseTLV = %#v, want %#v", avp.Value, want.Value)
	}

	// standard attribute
	avp, err = d.ParseTLV("", "Test-Std-TLV", TLVValue{Name: "Test-Std-TLV-Addr", Value: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if avp.Type != 173 || !bytes.Equal(avp.Value, []byte{3, 6, 192, 0, 2, 1}) {
		t.Errorf("ParseTLV standard = %#v", avp)
	}

	// BEGIN-TLV children
	avp, err = d.ParseTLV("TLVVendor", "TLV-Block", TLVValue{Name: "TLV-Block-Inner-Name", Value: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := vsaAVP(testTLVVendorID, 3, []byte{2, 5, 1, 3, 'x'}); !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("ParseTLV block = %#v, want %#v", avp.Value, want.Value)
	}
}

func TestParseTLVErrors(t *testing.T) {
	d := loadTLVTestDict(t)
	tests := []struct {
		name   string
		vendor string
		attr   string
		values []TLVValue
		want   error
	}{
		{"unknown vendor", "Nope", "TLV-Remote", nil, ErrUnknownVendor},
		{"unknown attribute", "TLVVendor", "Nope", nil, ErrUnknownAttribute},
		{"child as root", "TLVVendor", "TLV-Remote-Nested", nil, ErrUnknownAttribute},
		{"not a tlv", "TLVVendor", "TLV-Plain", nil, ErrUnsupportedAttributeType},
		{"no values", "TLVVendor", "TLV-Remote", nil, ErrInvalidValue},
		{"unknown child", "TLVVendor", "TLV-Remote", []TLVValue{{Name: "Nope", Value: "1"}}, ErrUnknownAttribute},
		{"foreign child", "TLVVendor", "TLV-Remote", []TLVValue{{Name: "TLV-Block-Id", Value: "1"}}, ErrUnknownAttribute},
		{"tlv child with value", "TLVVendor", "TLV-Remote", []TLVValue{{Name: "TLV-Remote-Nested", Value: "1"}}, ErrInvalidValue},
		{"unsupported vendor format", "TLVWide", "TW-Capability", []TLVValue{{Name: "TW-Release", Value: "1"}}, ErrUnsupportedAttributeType},
		{"bad value", "TLVVendor", "TLV-Remote", []TLVValue{{Name: "TLV-Remote-Mask", Value: "x"}}, ErrInvalidValue},
		{"too long", "TLVVendor", "TLV-Remote", []TLVValue{{Name: "TLV-Remote-Nested-Name", Value: strings.Repeat("a", 254)}}, ErrInvalidValue},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.ParseTLV(tt.vendor, tt.attr, tt.values...)
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if avp := d.NewTLV("Nope", "TLV-Remote"); avp.Type != 0 || avp.Value != nil {
		t.Errorf("NewTLV on error = %#v, want zero AVP", avp)
	}
}

func TestTLVPacketRoundTrip(t *testing.T) {
	d := loadTLVTestDict(t)
	secret := "secret"
	req := Request(AccessRequest, secret)
	req.AddAVP(d.NewTLV("TLVVendor", "TLV-Remote",
		TLVValue{Name: "TLV-Remote-Addr", Value: "10.0.0.1"},
		TLVValue{Name: "TLV-Remote-Nested-Count", Value: "7"},
	))
	req.AddAVP(d.NewTLV("", "Test-Std-TLV", TLVValue{Name: "Test-Std-TLV-Len", Value: "24"}))
	buf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoders := map[string]func() (*Packet, error){
		"DecodeRequest":     func() (*Packet, error) { return DecodeRequest(secret, buf) },
		"DecodeRequestLazy": func() (*Packet, error) { return DecodeRequestLazy(secret, buf) },
	}
	for name, decode := range decoders {
		t.Run(name, func(t *testing.T) {
			p, err := decode()
			if err != nil {
				t.Fatal(err)
			}
			if v, ok := d.GetTLV(p, "TLVVendor", "TLV-Remote-Addr"); !ok || !bytes.Equal(v, []byte{10, 0, 0, 1}) {
				t.Errorf("GetTLV Addr = %v, %v", v, ok)
			}
			if s, ok := d.GetTLVString(p, "TLVVendor", "TLV-Remote-Nested-Count"); !ok || s != "7" {
				t.Errorf("GetTLVString Nested-Count = %q, %v", s, ok)
			}
			if s, ok := d.GetTLVString(p, "TLVVendor", "TLV-Remote-Nested"); !ok || s != "{TLV-Remote-Nested-Count: 7}" {
				t.Errorf("GetTLVString Nested = %q, %v", s, ok)
			}
			if s, ok := d.GetTLVString(p, "", "Test-Std-TLV-Len"); !ok || s != "24" {
				t.Errorf("GetTLVString Std-Len = %q, %v", s, ok)
			}
			for _, name := range []string{"TLV-Remote-Mask", "TLV-Block-Id", "Nope", "TLV-Plain"} {
				if v, ok := d.GetTLV(p, "TLVVendor", name); ok {
					t.Errorf("GetTLV %s = %v, want not found", name, v)
				}
			}
			if _, ok := d.GetTLV(p, "Nope", "TLV-Remote-Addr"); ok {
				t.Error("GetTLV unknown vendor found")
			}
		})
	}
}

func TestTLVValueNames(t *testing.T) {
	d := loadTLVTestDict(t)
	p := Request(AccessRequest, "secret")
	p.AddAVP(vsaAVP(testTLVVendorID, 2, []byte{3, 4, 0, 1}))
	if s, ok := d.GetTLVString(p, "TLVVendor", "TLV-Remote-Qualifier"); !ok || s != "Exact" {
		t.Errorf("GetTLVString = %q, %v", s, ok)
	}
	// malformed parent: child not found
	p = Request(AccessRequest, "secret")
	p.AddAVP(vsaAVP(testTLVVendorID, 2, []byte{3, 4, 0, 1, 7}))
	if _, ok := d.GetTLV(p, "TLVVendor", "TLV-Remote-Qualifier"); ok {
		t.Error("GetTLV found child in malformed TLV")
	}
}

func FuzzTLVDecode(f *testing.F) {
	d := loadTLVTestDict(f)
	f.Add(remoteValue)
	f.Add([]byte{1, 6, 0, 0, 0, 1, 2, 5, 1, 3, 'x'})
	f.Add([]byte{4, 4, 1, 9})
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > DefaultVendorFormat.maxValueLen() {
			return
		}
		p := Request(AccessRequest, "secret")
		p.AddAVP(vsaAVP(testTLVVendorID, 2, value))
		p.AddAVP(vsaAVP(testTLVVendorID, 3, value))
		p.AddAVP(AVP{Type: 173, Value: value})
		p.EachAVP(func(a AVP) bool {
			_ = d.DecodeAVPValue(p, a)
			return true
		})
		for _, name := range []string{"TLV-Remote-Nested-Name", "TLV-Remote-Qualifier", "TLV-Block-Inner-Name", "TLV-Remote-Nested"} {
			_, _ = d.GetTLV(p, "TLVVendor", name)
			_, _ = d.GetTLVString(p, "TLVVendor", name)
		}
		_, _ = d.GetTLVString(p, "", "Test-Std-TLV-Addr")
	})
}

// loadTLVDict loads dict text into a new dictionary.
func loadTLVDict(t testing.TB, dict string) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("tlv_test", strings.NewReader(dict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

// Templates send a tlv attribute's value as raw octets.
func TestTLVTemplateRawOctets(t *testing.T) {
	d := loadTLVTestDict(t)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })

	raw := "\x01\x06\x00\x00\x00\x05"
	byType := &RequestTemplate{code: AccessRequest}
	byType.AddAttributeTypes(173)
	byName, err := d.CreateRequestTemplate(AccessRequest, "Test-Std-TLV")
	if err != nil {
		t.Fatal(err)
	}
	for name, tmpl := range map[string]*RequestTemplate{"AddAttributeTypes": byType, "CreateRequestTemplate": byName} {
		p := Request(AccessRequest, "secret")
		tmpl.Fill(p, raw)
		if avp := p.GetAVP(173); avp == nil || string(avp.Value) != raw {
			t.Errorf("%s: AVP = %#v, want raw value", name, avp)
		}
	}
}

// Redeclaring a TLV parent keeps its sub-attributes.
func TestTLVParentRedefinition(t *testing.T) {
	d := loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE A 200 tlv\n")
	avp, err := d.ParseTLV("", "A", TLVValue{Name: "A-1", Value: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.DecodeAVPValue(nil, avp); got != "{A-1: 1}" {
		t.Errorf("DecodeAVPValue = %q", got)
	}
}

// Unclosed BEGIN-TLV and vendor changes inside a TLV block are errors.
func TestTLVBlockMisuse(t *testing.T) {
	tests := []struct{ name, dict string }{
		{"unclosed at EOF", "ATTRIBUTE A 1 tlv\nBEGIN-TLV A\nATTRIBUTE B 1 integer"},
		{"BEGIN-VENDOR inside", "VENDOR V 1\nATTRIBUTE A 1 tlv\nBEGIN-TLV A\nBEGIN-VENDOR V\nEND-VENDOR V\nEND-TLV A"},
		{"END-VENDOR inside", "VENDOR V 1\nBEGIN-VENDOR V\nATTRIBUTE A 1 tlv\nBEGIN-TLV A\nEND-VENDOR V"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDictionary()
			if err := d.loadReader("bad", strings.NewReader(tt.dict)); err == nil {
				t.Error("expected error")
			}
		})
	}

	// an unclosed block doesn't leak into the next file
	dir := t.TempDir()
	a, b := dir+"/a", dir+"/b"
	writeFile(t, a, "ATTRIBUTE A 1 tlv\nBEGIN-TLV A\n")
	writeFile(t, b, "ATTRIBUTE Foo 5 string\n")
	d := NewDictionary()
	if err := d.LoadFile(a); err == nil {
		t.Error("LoadFile with unclosed BEGIN-TLV: expected error")
	}
	if err := d.LoadFile(b); err != nil || !d.HasAttribute("Foo") {
		t.Errorf("next file: err=%v, Foo defined=%v", err, d.HasAttribute("Foo"))
	}

	// $INCLUDE inside a block is an error
	writeFile(t, dir+"/inc", "ATTRIBUTE Bar 6 string\n")
	writeFile(t, dir+"/root", "ATTRIBUTE T 200 tlv\nBEGIN-TLV T\n$INCLUDE inc\nEND-TLV T\n")
	if err := NewDictionary().LoadFile(dir + "/root"); err == nil {
		t.Error("$INCLUDE inside BEGIN-TLV: expected error")
	}

	// a parse error inside a block doesn't leak the block either
	d = NewDictionary()
	if err := d.loadReader("bad", strings.NewReader("ATTRIBUTE A 1 tlv\nBEGIN-TLV A\nVALUE\n")); err == nil {
		t.Fatal("expected parse error")
	}
	d.loadReader("next", strings.NewReader("ATTRIBUTE Foo 5 string\n"))
	if !d.HasAttribute("Foo") {
		t.Error("attribute after failed file became a sub-attribute")
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ParseTLV can't build encrypted sub-attributes (they'd go out in clear); has_tag is ignored.
func TestTLVChildFlags(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-P 200.1 string encrypt=1\nATTRIBUTE A-T 200.2 integer has_tag\nATTRIBUTE A-K 200.3 octets encrypt=2\n")
	for _, name := range []string{"A-P", "A-K"} {
		if _, err := d.ParseTLV("", "A", TLVValue{Name: name, Value: "pw"}); !errors.Is(err, ErrEncryptedAttribute) {
			t.Errorf("ParseTLV %s: err = %v", name, err)
		}
	}
	avp, err := d.ParseTLV("", "A", TLVValue{Name: "A-T", Value: "7"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.DecodeAVPValue(nil, avp); got != "{A-T: 7}" {
		t.Errorf("DecodeAVPValue = %q", got)
	}
	if n := strings.Count(h.all(), "ignoring has_tag of sub-attribute"); n != 1 {
		t.Errorf("has_tag warnings = %d, want 1:\n%s", n, h.all())
	}
	if n := h.count(slog.LevelWarn, "encrypt"); n != 0 {
		t.Errorf("encrypt warnings = %d, want 0:\n%s", n, h.all())
	}
}

// A second sub-attribute with the same number is skipped with a warning.
func TestTLVDuplicateChildNumber(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-X 200.1 integer\nATTRIBUTE A-Y 200.1 integer\n")
	if got := d.DecodeAVPValue(nil, AVP{Type: 200, Value: []byte{1, 6, 0, 0, 0, 1}}); got != "{A-X: 1}" {
		t.Errorf("DecodeAVPValue = %q, want first definition", got)
	}
	if _, err := d.ParseTLV("", "A", TLVValue{Name: "A-Y", Value: "1"}); !errors.Is(err, ErrUnknownAttribute) {
		t.Errorf("ParseTLV duplicate: err = %v", err)
	}
	if !strings.Contains(h.all(), "duplicate sub-attribute number") {
		t.Errorf("no duplicate warning:\n%s", h.all())
	}
}

// Sub-attributes of a non-TLV parent are warned about; unsupported parents stay quiet.
func TestTLVNonTLVParent(t *testing.T) {
	h := useRecordLogger(t)
	loadTLVDict(t, `
ATTRIBUTE U 1 string
ATTRIBUTE U-X 1.1 integer
ATTRIBUTE A 200 tlv
ATTRIBUTE A-1 200.1 integer
ATTRIBUTE A-1-X 200.1.1 integer
ATTRIBUTE E 241 extended
ATTRIBUTE E-1 241.1 integer
ATTRIBUTE V 241.26 evs
VENDOR W 9 format=2,1
BEGIN-VENDOR W
ATTRIBUTE W-T 1 tlv
ATTRIBUTE W-T-1 1.1 integer
END-VENDOR W
`)
	all := h.all()
	if n := strings.Count(all, "parent is not a TLV"); n != 2 {
		t.Errorf("non-TLV parent warnings = %d, want 2 (U-X, A-1-X):\n%s", n, all)
	}
	if n := strings.Count(all, "ignoring unsupported sub-attribute"); n != 1 {
		t.Errorf("unsupported sub-attribute debug logs = %d, want 1 (W-T-1):\n%s", n, all)
	}
}

// Naming a nested TLV with an empty value starts a new instance of it.
func TestParseTLVNewNestedInstance(t *testing.T) {
	d := loadTLVTestDict(t)
	avp, err := d.ParseTLV("TLVVendor", "TLV-Remote",
		TLVValue{Name: "TLV-Remote-Nested-Name", Value: "a"},
		TLVValue{Name: "TLV-Remote-Nested"},
		TLVValue{Name: "TLV-Remote-Nested-Name", Value: "b"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := vsaAVP(testTLVVendorID, 2, []byte{4, 5, 1, 3, 'a', 4, 5, 1, 3, 'b'})
	if !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("ParseTLV = %v, want %v", avp.Value, want.Value)
	}
	// a nested TLV holds one or more sub-attributes (RFC 6929)
	for _, values := range [][]TLVValue{
		{{Name: "TLV-Remote-Nested"}},
		{{Name: "TLV-Remote-Nested-Name", Value: "a"}, {Name: "TLV-Remote-Nested"}},
	} {
		if _, err := d.ParseTLV("TLVVendor", "TLV-Remote", values...); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("empty instance %v: err = %v", values, err)
		}
	}
}

// Redeclaring an attribute name with another definition is an error; an identical one is not.
func TestDictionaryNameConflict(t *testing.T) {
	tests := []struct{ name, dict string }{
		{"top-level number", "ATTRIBUTE A 200 integer\nATTRIBUTE A 201 integer\n"},
		{"top-level type", "ATTRIBUTE A 200 integer\nATTRIBUTE A 200 string\n"},
		{"octets vs ipv6prefix", "ATTRIBUTE A 200 octets\nATTRIBUTE A 200 ipv6prefix\n"},
		{"octets vs ifid", "ATTRIBUTE A 200 octets\nATTRIBUTE A 200 ifid\n"},
		{"integer vs date", "ATTRIBUTE A 200 integer\nATTRIBUTE A 200 date\n"},
		{"top-level flags", "ATTRIBUTE A 200 string\nATTRIBUTE A 200 string encrypt=1\n"},
		{"TLV number", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE A 201 tlv\n"},
		{"TLV to plain", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE A 200 integer\n"},
		{"vendor", "VENDOR V 9\nBEGIN-VENDOR V\nATTRIBUTE A 1 integer\nATTRIBUTE A 2 integer\nEND-VENDOR V\n"},
		{"child number", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE A-1 200.2 integer\n"},
		{"child type", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE A-1 200.1 string\n"},
		{"child parent", "ATTRIBUTE A 200 tlv\nATTRIBUTE B 201 tlv\nATTRIBUTE X 200.1 integer\nATTRIBUTE X 201.1 integer\n"},
		{"child after top-level", "ATTRIBUTE X 5 integer\nATTRIBUTE A 200 tlv\nATTRIBUTE X 200.1 integer\n"},
		{"top-level after child", "ATTRIBUTE A 200 tlv\nATTRIBUTE X 200.1 integer\nATTRIBUTE X 5 integer\n"},
		{"child encrypt", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 string\nATTRIBUTE A-1 200.1 string encrypt=2\n"},
		{"child encrypt method", "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 string encrypt=1\nATTRIBUTE A-1 200.1 string encrypt=2\n"},
		{"TLV encrypt", "ATTRIBUTE A 200 tlv\nATTRIBUTE A 200 tlv encrypt=2\n"},
		{"vendor TLV encrypt", "VENDOR V 9\nBEGIN-VENDOR V\nATTRIBUTE A 1 tlv encrypt=2\nATTRIBUTE A 1 tlv\nEND-VENDOR V\n"},
		{"integer encrypt", "ATTRIBUTE A 5 integer\nATTRIBUTE A 5 integer encrypt=2\n"},
		{"octets encrypt=3", "ATTRIBUTE A 5 octets\nATTRIBUTE A 5 octets encrypt=3\n"},
		{"string encrypt=3", "ATTRIBUTE A 5 octets\nATTRIBUTE A 5 string encrypt=3\n"},
		{"password vs encrypt=2", "ATTRIBUTE A 5 password\nATTRIBUTE A 5 integer encrypt=2\n"},
		{"vendor integer encrypt", "VENDOR V 9\nBEGIN-VENDOR V\nATTRIBUTE A 1 integer encrypt=1\nATTRIBUTE A 1 integer\nEND-VENDOR V\n"},
		{"extended encrypt", "ATTRIBUTE E 241 extended\nATTRIBUTE A 241.8 octets\nATTRIBUTE A 241.8 octets encrypt=3\n"},
		{"extended encrypt method", "ATTRIBUTE E 241 extended\nATTRIBUTE A 241.8 octets encrypt=1\nATTRIBUTE A 241.8 octets encrypt=2\n"},
		{"extended tlv encrypt method", "ATTRIBUTE E 241 extended\nATTRIBUTE A 241.7 tlv encrypt=1\nATTRIBUTE A 241.7 tlv encrypt=2\n"},
		{"EVS encrypt method", "ATTRIBUTE E 241 extended\nATTRIBUTE EVS 241.26 evs\nVENDOR V 9\nBEGIN-VENDOR V format=EVS\nATTRIBUTE A 1 string encrypt=1\nATTRIBUTE A 1 string encrypt=2\nEND-VENDOR V\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewDictionary().loadReader("bad", strings.NewReader(tt.dict))
			if err == nil || !strings.Contains(err.Error(), "duplicate attribute") {
				t.Errorf("err = %v, want duplicate attribute", err)
			}
		})
	}

	d := loadTLVDict(t, `
ATTRIBUTE X 5 string encrypt=1
ATTRIBUTE X 5 string encrypt=1
VENDOR V 9
BEGIN-VENDOR V
ATTRIBUTE X 5 integer
ATTRIBUTE A 200 tlv
ATTRIBUTE A-1 200.1 integer
ATTRIBUTE A-1 200.1 integer
END-VENDOR V
`)
	if _, err := d.ParseTLV("V", "A", TLVValue{Name: "A-1", Value: "1"}); err != nil {
		t.Errorf("identical redeclaration: %v", err)
	}
}

// Another name for a number is an alias: each name encodes with its own type, the last one decodes.
func TestDictionaryNumberAlias(t *testing.T) {
	d := loadTLVDict(t, `
ATTRIBUTE A 200 tlv
ATTRIBUTE A-1 200.1 integer
ATTRIBUTE B 200 integer
`)
	avp, err := d.ParseTLV("", "A", TLVValue{Name: "A-1", Value: "1"})
	if err != nil {
		t.Fatalf("ParseTLV old name: %v", err)
	}
	if got := d.DecodeAVPValue(nil, avp); got != "17170432" {
		t.Errorf("DecodeAVPValue = %q, want the last name's type", got)
	}
	if avp, err := d.ParseAVP("B", "5"); err != nil || avp.Type != 200 {
		t.Errorf("ParseAVP new name = %v, %v", avp, err)
	}
	// a TLV alias shares the sub-attributes
	d = loadTLVDict(t, `
ATTRIBUTE A 200 tlv
ATTRIBUTE A-1 200.1 integer
ATTRIBUTE B 200 tlv
BEGIN-TLV B
ATTRIBUTE B-2 2 integer
END-TLV B
ATTRIBUTE A-3 200.3 integer
`)
	// both names build the same attribute; it decodes with all sub-attributes
	for _, name := range []string{"A", "B"} {
		avp, err := d.ParseTLV("", name, TLVValue{Name: "A-1", Value: "1"}, TLVValue{Name: "B-2", Value: "2"}, TLVValue{Name: "A-3", Value: "3"})
		if err != nil {
			t.Fatalf("ParseTLV %s: %v", name, err)
		}
		if got := d.DecodeAVPValue(nil, avp); got != "{A-1: 1, B-2: 2, A-3: 3}" {
			t.Errorf("%s: DecodeAVPValue = %q", name, got)
		}
	}
}

// A sub-attribute skipped under one vendor doesn't hide an unknown name under another.
func TestTLVSkippedNamePerVendor(t *testing.T) {
	h := useRecordLogger(t)
	d := NewDictionary()
	err := d.loadReader("bad", strings.NewReader(`
VENDOR V1 1
VENDOR V2 2
BEGIN-VENDOR V1
ATTRIBUTE X 9.1 integer
END-VENDOR V1
BEGIN-VENDOR V2
VALUE X One 1
BEGIN-TLV X
ATTRIBUTE Y 1 integer
END-TLV X
END-VENDOR V2
`))
	if err == nil || !strings.Contains(err.Error(), "Unknown TLV attribute X") {
		t.Errorf("err = %v, want unknown TLV", err)
	}
	if !strings.Contains(h.all(), "ignoring value for unknown attribute") {
		t.Errorf("VALUE of unknown X not warned:\n%s", h.all())
	}
}

// Formatting a tlv value without a default dictionary doesn't panic.
func TestAvpTLVStringNoDictionary(t *testing.T) {
	old := GetDefaultDictionary()
	SetDefaultDictionary(nil)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	if got := avpTLV.String(nil, AVP{Type: 200, Value: []byte{1, 3, 'a'}}); got != avpBinary.String(nil, AVP{Value: []byte{1, 3, 'a'}}) {
		t.Errorf("String = %q", got)
	}
}

// An invalid IP address, or one of the other family, is an error, not an empty value.
func TestParseInvalidIP(t *testing.T) {
	d := loadTLVDict(t, `
ATTRIBUTE IP 8 ipaddr
ATTRIBUTE IP6 168 ipv6addr
ATTRIBUTE A 200 tlv
ATTRIBUTE A-IP 200.1 ipaddr
ATTRIBUTE A-IP6 200.2 ipv6addr
`)
	tests := []struct{ ipv4, ipv6 string }{
		{"garbage", "garbage"},
		{"2001:db8::1", "192.0.2.1"},
	}
	for _, tt := range tests {
		if _, err := d.ParseTLV("", "A", TLVValue{Name: "A-IP", Value: tt.ipv4}); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseTLV ipaddr %q: err = %v", tt.ipv4, err)
		}
		if _, err := d.ParseTLV("", "A", TLVValue{Name: "A-IP6", Value: tt.ipv6}); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseTLV ipv6addr %q: err = %v", tt.ipv6, err)
		}
		if _, err := d.ParseAVP("IP", tt.ipv4); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseAVP ipaddr %q: err = %v", tt.ipv4, err)
		}
		if _, err := d.ParseAVP("IP6", tt.ipv6); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseAVP ipv6addr %q: err = %v", tt.ipv6, err)
		}
	}
	if avp, err := d.ParseAVP("IP6", "2001:db8::1"); err != nil || len(avp.Value) != net.IPv6len {
		t.Errorf("ParseAVP ipv6addr = %v, %v", avp.Value, err)
	}
}

// GetTLV looks at every vendor sub-attribute of a Vendor-Specific attribute, also in pooled packets.
func TestGetTLVMultipleVSAs(t *testing.T) {
	d := loadTLVTestDict(t)
	value := []byte{0, 0, 0x27, 0x0e}              // vendor 9998
	value = append(value, 1, 6, 0, 0, 0, 5)        // TLV-Plain
	value = append(value, 2, 8, 2, 6, 0, 0, 0, 24) // TLV-Remote{Mask}
	req := Request(AccessRequest, "secret")
	req.AddAVP(AVP{Type: AttrVendorSpecific, Value: value})
	buf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeRequestPooled("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := d.GetTLV(p, "TLVVendor", "TLV-Remote-Mask")
	p.Release()
	if !ok || !bytes.Equal(got, []byte{0, 0, 0, 24}) {
		t.Errorf("GetTLV = %v, %v", got, ok)
	}
}

// Only a format= argument sets the vendor format; redeclaring with 1,1 re-enables TLVs.
func TestTLVVendorFormatArgument(t *testing.T) {
	d := loadTLVDict(t, `
VENDOR V 9 # trailing comment
VENDOR S 8 format=2,1
VENDOR S 8 format=1,1
BEGIN-VENDOR V
ATTRIBUTE V-T 1 tlv
ATTRIBUTE V-T-1 1.1 integer
END-VENDOR V
BEGIN-VENDOR S
ATTRIBUTE S-T 1 tlv
ATTRIBUTE S-T-1 1.1 integer
END-VENDOR S
`)
	for _, c := range [][3]string{{"V", "V-T", "V-T-1"}, {"S", "S-T", "S-T-1"}} {
		if _, err := d.ParseTLV(c[0], c[1], TLVValue{Name: c[2], Value: "1"}); err != nil {
			t.Errorf("%s: %v", c[1], err)
		}
	}
}

// Flags other than encrypt= and has_tag (array, trailing comments) don't warn.
func TestTLVChildOtherFlagsQuiet(t *testing.T) {
	h := useRecordLogger(t)
	loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 ipaddr array\nATTRIBUTE A-2 200.2 integer # comment\n")
	if strings.Contains(h.all(), "ignoring has_tag") {
		t.Errorf("unexpected flag warning:\n%s", h.all())
	}
}

// VSA templates send a vendor tlv attribute's value as raw octets.
func TestTLVVSATemplateRawOctets(t *testing.T) {
	d := loadTLVTestDict(t)
	tmpl := &RequestTemplate{code: AccessRequest}
	if err := tmpl.AddVSAAttribute(d, "TLVVendor", "TLV-Remote"); err != nil {
		t.Fatal(err)
	}
	p := Request(AccessRequest, "secret")
	tmpl.Fill(p, "\x02\x06\x00\x00\x00\x18")
	want := vsaAVP(testTLVVendorID, 2, []byte{2, 6, 0, 0, 0, 24})
	if avp := p.GetAVP(AttrVendorSpecific); avp == nil || !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("AVP = %#v, want %#v", avp, want)
	}
}

// The README example, with the 3GPP2 definitions from FreeRADIUS.
func TestTLVReadmeExample(t *testing.T) {
	dict := loadTLVDict(t, `
VENDOR		3GPP2				5535
BEGIN-VENDOR	3GPP2
ATTRIBUTE	3GPP2-Remote-IP-Address			59	tlv
ATTRIBUTE	3GPP2-Remote-IP-Address-Value		59.1	ipaddr
ATTRIBUTE	3GPP2-Remote-IP-Address-Mask		59.2	integer
ATTRIBUTE	3GPP2-Remote-IP-Qualifier		59.3	short
END-VENDOR 3GPP2
`)
	avp, err := dict.ParseTLV("3GPP2", "3GPP2-Remote-IP-Address",
		TLVValue{Name: "3GPP2-Remote-IP-Address-Value", Value: "10.1.2.3"},
		TLVValue{Name: "3GPP2-Remote-IP-Qualifier", Value: "1"},
	)
	if err != nil {
		t.Fatal(err)
	}
	req := Request(AccessRequest, "secret")
	req.AddAVP(avp)
	buf, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeRequest("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	if q, ok := dict.GetTLVString(p, "3GPP2", "3GPP2-Remote-IP-Qualifier"); !ok || q != "1" {
		t.Errorf("GetTLVString = %q, %v", q, ok)
	}
}

// Invalid dotted ids are skipped with a warning.
func TestTLVInvalidOID(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, `
ATTRIBUTE A 59 tlv
ATTRIBUTE A-Big 59.300 integer
ATTRIBUTE A-Empty 59. integer
ATTRIBUTE A-Name a.b integer
`)
	if n := h.count(slog.LevelWarn, "ignoring attribute with invalid id"); n != 3 {
		t.Errorf("invalid id warnings = %d, want 3:\n%s", n, h.all())
	}
	for _, name := range []string{"A-Big", "A-Empty", "A-Name"} {
		if _, err := d.ParseTLV("", "A", TLVValue{Name: name, Value: "1"}); !errors.Is(err, ErrUnknownAttribute) {
			t.Errorf("ParseTLV %s: err = %v", name, err)
		}
	}
}

// Many small sub-attributes can exceed the attribute length; a VSA has less room.
func TestParseTLVTooManyChildren(t *testing.T) {
	d := loadTLVTestDict(t)
	masks := func(n int) []TLVValue { // 6 bytes each
		v := make([]TLVValue, n)
		for i := range v {
			v[i] = TLVValue{Name: "TLV-Remote-Mask", Value: "1"}
		}
		return v
	}
	if _, err := d.ParseTLV("TLVVendor", "TLV-Remote", masks(41)...); err != nil {
		t.Errorf("246 bytes: %v", err)
	}
	// 252 bytes fit a standard attribute but not a VSA
	if _, err := d.ParseTLV("TLVVendor", "TLV-Remote", masks(42)...); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("252 bytes in VSA: err = %v", err)
	}
	lens := make([]TLVValue, 43) // 258 bytes
	for i := range lens {
		lens[i] = TLVValue{Name: "Test-Std-TLV-Len", Value: "1"}
	}
	if _, err := d.ParseTLV("", "Test-Std-TLV", lens...); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("258 bytes: err = %v", err)
	}
}

// GetTLV with a top-level TLV name returns the whole value.
func TestGetTLVTopLevel(t *testing.T) {
	d := loadTLVTestDict(t)
	p := Request(AccessRequest, "secret")
	p.AddAVP(vsaAVP(testTLVVendorID, 2, remoteValue))
	p.AddAVP(AVP{Type: 173, Value: []byte{1, 6, 0, 0, 0, 24}})
	if v, ok := d.GetTLV(p, "TLVVendor", "TLV-Remote"); !ok || !bytes.Equal(v, remoteValue) {
		t.Errorf("GetTLV = %v, %v", v, ok)
	}
	if s, ok := d.GetTLVString(p, "", "Test-Std-TLV"); !ok || s != "{Test-Std-TLV-Len: 24}" {
		t.Errorf("GetTLVString = %q, %v", s, ok)
	}
}

// VALUEs of unsupported sub-attributes (2-byte vendor types) are logged at Debug only.
func TestTLVUnsupportedValueQuiet(t *testing.T) {
	h := useRecordLogger(t)
	loadTLVTestDict(t)
	for _, name := range []string{"TW-Flow-Id"} {
		if n := h.count(slog.LevelDebug, "attribute="+name+" value="); n != 1 {
			t.Errorf("%s: debug logs = %d, want 1:\n%s", name, n, h.all())
		}
	}
	if n := h.count(slog.LevelWarn, "value"); n != 0 {
		t.Errorf("value warnings = %d, want 0:\n%s", n, h.all())
	}
}

// Loading files while decoding TLVs is race-free.
func TestTLVConcurrentLoad(t *testing.T) {
	d := loadTLVTestDict(t)
	file := t.TempDir() + "/dict"
	writeFile(t, file, "ATTRIBUTE B 200 tlv\nATTRIBUTE B-1 200.1 integer\n")
	p := Request(AccessRequest, "secret")
	p.AddAVP(vsaAVP(testTLVVendorID, 2, remoteValue))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				if err := d.LoadFile(file); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				d.DecodeAVPValue(p, p.AVPs[0])
				d.GetTLVString(p, "TLVVendor", "TLV-Remote-Nested")
				d.ParseTLV("", "B", TLVValue{Name: "B-1", Value: "1"})
			}
		}()
	}
	wg.Wait()
}

// Packet.String renders TLVs with the default dictionary.
func TestTLVPacketString(t *testing.T) {
	d := loadTLVTestDict(t)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	p := Request(AccessRequest, "secret")
	p.AddAVP(d.NewTLV("", "Test-Std-TLV", TLVValue{Name: "Test-Std-TLV-Len", Value: "24"}))
	want := "AVP type: Test-Std-TLV {Test-Std-TLV-Len: 24}\n"
	if got := p.String(); !strings.Contains(got, want) {
		t.Errorf("Packet.String = %q, want %q", got, want)
	}
}

// AVP.String and Packet.String render VSAs, vendor TLVs included, with the default dictionary.
func TestVSAString(t *testing.T) {
	// Vendor-Specific comes from the builtin dictionary
	d := NewDictionary()
	if err := d.LoadBuiltin(); err != nil {
		t.Fatal(err)
	}
	if err := d.loadReader("tlv_test", strings.NewReader(tlvTestDict)); err != nil {
		t.Fatal(err)
	}
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })

	tlv := d.NewTLV("TLVVendor", "TLV-Remote", TLVValue{Name: "TLV-Remote-Qualifier", Value: "Exact"})
	plain := vsaAVP(testTLVVendorID, 1, []byte{0, 0, 0, 5})
	tests := []struct {
		avp  AVP
		want string
	}{
		{tlv, "AVP type: Vendor-Specific {Vendor:TLVVendor #9998, Attr: TLV-Remote #2, Value: {TLV-Remote-Qualifier: Exact}}"},
		{plain, "AVP type: Vendor-Specific {Vendor:TLVVendor #9998, Attr: TLV-Plain #1, Value: 5}"},
	}
	p := Request(AccessRequest, "secret")
	for _, tt := range tests {
		if got := tt.avp.String(); got != tt.want {
			t.Errorf("AVP.String = %q, want %q", got, tt.want)
		}
		p.AddAVP(tt.avp)
	}
	for _, tt := range tests {
		if got := p.String(); !strings.Contains(got, tt.want+"\n") {
			t.Errorf("Packet.String = %q, want %q", got, tt.want)
		}
	}

	// another attribute of type vsa doesn't recurse
	vsaDict := loadTLVDict(t, "ATTRIBUTE Other-VSA 100 vsa\n")
	SetDefaultDictionary(vsaDict)
	other := AVP{Type: 100, Value: plain.Value}
	if got := other.String(); got != "AVP type: Other-VSA {Vendor: 9998, Attr: 1, Value: []byte{0x0, 0x0, 0x0, 0x5}}" {
		t.Errorf("other vsa AVP.String = %q", got)
	}

	// without a default dictionary the VSA is shown raw
	SetDefaultDictionary(nil)
	if got := avpVendor.String(nil, plain); got != "{Vendor: 9998, Attr: 1, Value: []byte{0x0, 0x0, 0x0, 0x5}}" {
		t.Errorf("String without dictionary = %q", got)
	}
}

// Definitions with the same effective type or wire format are not conflicts, e.g. builtin and FreeRADIUS ones.
func TestDictionaryEquivalentRedeclaration(t *testing.T) {
	pairs := [][2]string{
		{"ATTRIBUTE User-Password 2 password", "ATTRIBUTE User-Password 2 string encrypt=1"},
		{"ATTRIBUTE Tunnel-Password 69 tunnel-password", "ATTRIBUTE Tunnel-Password 69 string has_tag,encrypt=2"},
		{"ATTRIBUTE Tunnel-Type 64 integer has_tag", "ATTRIBUTE Tunnel-Type 64 tagged-integer"},
		{"ATTRIBUTE EAP-Message 79 eapmessage", "ATTRIBUTE EAP-Message 79 octets concat"},
	}
	const ext = "ATTRIBUTE Extended-Attribute-1 241 extended\n"
	pairs = append(pairs,
		[2]string{"ATTRIBUTE A 241.8 password", "ATTRIBUTE A 241.8 string encrypt=1"},
		[2]string{"ATTRIBUTE A 241.8 tunnel-password", "ATTRIBUTE A 241.8 octets encrypt=2"},
	)
	for _, p := range pairs {
		for _, dict := range []string{p[0] + "\n" + p[1], p[1] + "\n" + p[0]} {
			if err := NewDictionary().loadReader("equiv", strings.NewReader(ext+dict)); err != nil {
				t.Errorf("%q: %v", dict, err)
			}
		}
	}
	// the first definition is kept
	d := loadTLVDict(t, "ATTRIBUTE EAP-Message 79 eapmessage\nATTRIBUTE EAP-Message 79 octets concat\n")
	if got := d.attrType["EAP-Message"]; got != typeEAPMessage {
		t.Errorf("type = %q, want %q", got, typeEAPMessage)
	}
}

// Redeclaring a name makes it the decoding name of its number again.
func TestDictionaryRedeclareAliasDecodes(t *testing.T) {
	d := loadTLVDict(t, "ATTRIBUTE A 200 integer\nATTRIBUTE B 200 string\nATTRIBUTE A 200 integer\n")
	if got := d.DecodeAVPValue(nil, AVP{Type: 200, Value: []byte{0, 0, 0, 0x41}}); got != "65" {
		t.Errorf("DecodeAVPValue = %q, want A (integer)", got)
	}
}

// TLV aliases share sub-attributes even with a non-TLV alias between them.
func TestTLVAliasAfterNonTLVAlias(t *testing.T) {
	d := loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE B 200 octets\nATTRIBUTE C 200 tlv\n")
	avp, err := d.ParseTLV("", "C", TLVValue{Name: "A-1", Value: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.DecodeAVPValue(nil, avp); got != "{A-1: 1}" {
		t.Errorf("DecodeAVPValue = %q", got)
	}
}

// A VSA of an unknown vendor or attribute keeps the raw format.
func TestVSAStringUnknown(t *testing.T) {
	old := GetDefaultDictionary()
	SetDefaultDictionary(loadTLVTestDict(t))
	t.Cleanup(func() { SetDefaultDictionary(old) })
	tests := []struct {
		avp  AVP
		want string
	}{
		{vsaAVP(12345, 7, []byte("hi")), "{Vendor: 12345, Attr: 7, Value: []byte{0x68, 0x69}}"},
		{vsaAVP(testTLVVendorID, 99, []byte("hi")), "{Vendor:TLVVendor #9998, Attr: 99, Value: []byte{0x68, 0x69}}"},
	}
	for _, tt := range tests {
		if got := avpVendor.String(nil, tt.avp); got != tt.want {
			t.Errorf("String = %q, want %q", got, tt.want)
		}
	}
}
