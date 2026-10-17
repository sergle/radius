package radius

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

const testExtVendorID = 11344

// extTestDict declares RFC 6929 extended attributes as FreeRADIUS v3.2 does.
const extTestDict = `
ATTRIBUTE	Extended-Attribute-1		241	extended
ATTRIBUTE	Extended-Attribute-5		245	long-extended
ATTRIBUTE	Extended-Vendor-Specific-1	241.26	evs
ATTRIBUTE	Extended-Vendor-Specific-5	245.26	evs

ATTRIBUTE	Frag-Status			241.1	integer
VALUE	Frag-Status			More-Data-Pending	2
ATTRIBUTE	Ext-Name			241.8	string
ATTRIBUTE	Ext-Port-Info			241.5	tlv
ATTRIBUTE	Ext-Port-Type			241.5.1	integer
ATTRIBUTE	Ext-Port-Addr			241.5.3	ipaddr
VALUE	Ext-Port-Type			Static		1

ATTRIBUTE	Extended-Attribute-6		246	long-extended
ATTRIBUTE	Long6-Blob			246.1	octets

ATTRIBUTE	Long-Blob			245.1	octets
ATTRIBUTE	Long-Text			245.2	string
ATTRIBUTE	Long-TLV			245.3	tlv
BEGIN-TLV	Long-TLV
ATTRIBUTE	Long-TLV-Id			1	integer
END-TLV		Long-TLV

VENDOR		ExtVendor	11344
BEGIN-VENDOR	ExtVendor	format=Extended-Vendor-Specific-5
ATTRIBUTE	EV-Anonce			1	octets
ATTRIBUTE	EV-Count			2	integer
VALUE	EV-Count			Two		2
ATTRIBUTE	EV-T				3	tlv
ATTRIBUTE	EV-T-Id				3.1	integer
END-VENDOR	ExtVendor
BEGIN-VENDOR	ExtVendor	format=Extended-Vendor-Specific-1
ATTRIBUTE	EV1-Id				3	integer
END-VENDOR	ExtVendor
BEGIN-VENDOR	ExtVendor
ATTRIBUTE	EV-Plain			1	string
END-VENDOR	ExtVendor
`

func loadExtTestDict(t testing.TB) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("ext_test", strings.NewReader(extTestDict)); err != nil {
		t.Fatalf("loadReader: %v", err)
	}
	return d
}

// useExtDefault makes the extended test dictionary the default one for the test.
func useExtDefault(t *testing.T) *Dictionary {
	d := loadExtTestDict(t)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	return d
}

// extLong returns a long-extended AVP with flags and data.
func extLong(typ AttributeType, ext, flags uint8, data ...byte) AVP {
	return AVP{Type: typ, Value: append([]byte{ext, flags}, data...)}
}

// extMore returns a full-length long-extended AVP with the More flag: data padded with fill.
func extMore(typ AttributeType, ext, fill uint8, data ...byte) AVP {
	pad := bytes.Repeat([]byte{fill}, maxLongExtData-len(data))
	return extLong(typ, ext, extMoreFlag, append(pad, data...)...)
}

func TestExtendedDictionaryLoad(t *testing.T) {
	h := useRecordLogger(t)
	d := loadExtTestDict(t)
	if n := h.count(slog.LevelWarn, ""); n != 0 {
		t.Errorf("warnings:\n%s", h.all())
	}
	if n := h.count(slog.LevelDebug, "ignoring"); n != 0 {
		t.Errorf("ignored definitions:\n%s", h.all())
	}
	// EVS attributes don't take VSA numbers of the vendor
	if name := d.GetVSAAttributeName(testExtVendorID, 1); name != "EV-Plain" {
		t.Errorf("VSA 1 = %q, want EV-Plain", name)
	}
	if d.HasVSAAttribute(testExtVendorID, "EV-Anonce") {
		t.Error("EV-Anonce loaded as a VSA")
	}
	// extended names aren't top-level numbers
	if d.HasAttribute("Frag-Status") {
		t.Error("Frag-Status is a top-level attribute")
	}
}

func TestParseAVPExtended(t *testing.T) {
	d := loadExtTestDict(t)
	tests := []struct {
		name, value string
		want        AVP
	}{
		{"Frag-Status", "More-Data-Pending", AVP{Type: 241, Value: []byte{1, 0, 0, 0, 2}}},
		{"Frag-Status", "7", AVP{Type: 241, Value: []byte{1, 0, 0, 0, 7}}},
		{"Ext-Name", "abc", AVP{Type: 241, Value: []byte{8, 'a', 'b', 'c'}}},
		{"Long-Text", "abc", AVP{Type: 245, Value: []byte{2, 0, 'a', 'b', 'c'}}},
	}
	for _, tt := range tests {
		got, err := d.ParseAVP(tt.name, tt.value)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got.Type != tt.want.Type || !bytes.Equal(got.Value, tt.want.Value) {
			t.Errorf("%s = %v, want %v", tt.name, got, tt.want)
		}
	}

	errTests := []struct {
		name, value string
		err         error
	}{
		{"Frag-Status", "Nope", ErrInvalidValue},
		{"Frag-Status:1", "2", ErrInvalidTag},
		{"Ext-Port-Info", "x", ErrUnsupportedAttributeType},
		{"Extended-Vendor-Specific-1", "x", ErrUnsupportedAttributeType},
		{"Long-Text", strings.Repeat("x", 300), ErrInvalidValue},
		{"Ext-Name", strings.Repeat("x", 253), ErrInvalidValue},
		{"EV-Count", "2", ErrUnknownAttribute},
	}
	for _, tt := range errTests {
		if _, err := d.ParseAVP(tt.name, tt.value); !errors.Is(err, tt.err) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.err)
		}
	}
}

func TestParseExtended(t *testing.T) {
	d := loadExtTestDict(t)
	e, err := d.ParseExtended("ExtVendor", "EV-Count", "Two")
	if err != nil {
		t.Fatal(err)
	}
	want := ExtendedAttr{Type: 245, ExtType: ExtTypeEVS, Vendor: testExtVendorID, VendorType: 2, Value: []byte{0, 0, 0, 2}}
	if e.Type != want.Type || e.ExtType != want.ExtType || e.Vendor != want.Vendor ||
		e.VendorType != want.VendorType || !bytes.Equal(e.Value, want.Value) {
		t.Errorf("ParseExtended = %+v, want %+v", e, want)
	}
	avps := e.ToAVPList()
	wantValue := []byte{26, 0, 0, 0, 0x2c, 0x50, 2, 0, 0, 0, 2}
	if len(avps) != 1 || avps[0].Type != 245 || !bytes.Equal(avps[0].Value, wantValue) {
		t.Errorf("ToAVPList = %v, want 245 %v", avps, wantValue)
	}

	e, err = d.ParseExtended("ExtVendor", "EV1-Id", "5")
	if err != nil {
		t.Fatal(err)
	}
	avps = e.ToAVPList()
	if wantValue := []byte{26, 0, 0, 0x2c, 0x50, 3, 0, 0, 0, 5}; len(avps) != 1 || avps[0].Type != 241 || !bytes.Equal(avps[0].Value, wantValue) {
		t.Errorf("EV1-Id = %v, want 241 %v", avps, wantValue)
	}

	e, err = d.ParseExtended("", "Frag-Status", "2")
	if err != nil || e.Type != 241 || e.ExtType != 1 {
		t.Errorf("Frag-Status = %+v, %v", e, err)
	}

	for _, c := range [][2]string{{"ExtVendor", "EV-Plain"}, {"Nope", "EV-Count"}, {"", "EV-Count"}, {"", "User-Name"}} {
		if _, err := d.ParseExtended(c[0], c[1], "1"); err == nil {
			t.Errorf("%s/%s: expected error", c[0], c[1])
		}
	}
}

// Long values are split over several AVPs, the More flag on all but the last, and joined on read.
func TestExtendedLongSplitJoin(t *testing.T) {
	d := loadExtTestDict(t)
	long := strings.Repeat("0123456789", 60)
	e, err := d.ParseExtended("", "Long-Text", long)
	if err != nil {
		t.Fatal(err)
	}
	p := Request(AccessRequest, "secret")
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte("u")})
	p.AddExtended(e)
	avps := p.AVPs[1:]
	if len(avps) != 3 {
		t.Fatalf("got %d AVPs, want 3", len(avps))
	}
	for i, a := range avps {
		more := i < len(avps)-1
		if a.Type != 245 || a.Value[0] != 2 || (a.Value[1]&extMoreFlag != 0) != more {
			t.Errorf("fragment %d header = %d %v", i, a.Type, a.Value[:2])
		}
		if more && len(a.Value) != maxAVPValueLen {
			t.Errorf("fragment %d len = %d, want %d", i, len(a.Value), maxAVPValueLen)
		}
	}

	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, decode := range []func(string, []byte) (*Packet, error){DecodeRequest, DecodeRequestLazy} {
		q, err := decode("secret", b)
		if err != nil {
			t.Fatal(err)
		}
		v, ok := d.GetExtended(q, "", "Long-Text")
		if !ok || string(v) != long {
			t.Errorf("GetExtended = %d bytes, %v", len(v), ok)
		}
	}

	// EVS: the vendor header is in the first fragment only
	anonce := bytes.Repeat([]byte{0xab}, 500)
	p = Request(AccessRequest, "secret")
	p.AddExtended(ExtendedAttr{Type: 245, ExtType: ExtTypeEVS, Vendor: testExtVendorID, VendorType: 1, Value: anonce})
	if len(p.AVPs) != 3 || !bytes.Equal(p.AVPs[0].Value[:7], []byte{26, extMoreFlag, 0, 0, 0x2c, 0x50, 1}) ||
		!bytes.Equal(p.AVPs[1].Value[:3], []byte{26, extMoreFlag, 0xab}) {
		t.Fatalf("EVS fragments = %v", p.AVPs)
	}
	if v, ok := d.GetExtended(p, "ExtVendor", "EV-Anonce"); !ok || !bytes.Equal(v, anonce) {
		t.Errorf("GetExtended EVS = %d bytes, %v", len(v), ok)
	}

	// a short value is one AVP without More
	e = ExtendedAttr{Type: 245, ExtType: 1, Value: []byte{7}}
	if avps := e.ToAVPList(); len(avps) != 1 || !bytes.Equal(avps[0].Value, []byte{1, 0, 7}) {
		t.Errorf("short long value = %v", avps)
	}
}

func TestExtendedTooLong(t *testing.T) {
	h := useRecordLogger(t)
	e := ExtendedAttr{Type: 241, ExtType: 1, Value: make([]byte, maxAVPValueLen)}
	if avps := e.ToAVPList(); avps != nil {
		t.Errorf("ToAVPList = %v, want nil", avps)
	}
	p := Request(AccessRequest, "secret")
	p.AddExtended(e)
	if len(p.AVPs) != 0 {
		t.Errorf("AddExtended added %v", p.AVPs)
	}
	if !strings.Contains(h.all(), "too long") {
		t.Errorf("no warning:\n%s", h.all())
	}
}

func TestGetExtended(t *testing.T) {
	d := loadExtTestDict(t)
	p := Request(AccessRequest, "secret")
	p.AddAVP(
		AVP{Type: 241, Value: []byte{8, 'x'}},
		AVP{Type: 241, Value: []byte{1, 0, 0, 0, 2}},
		AVP{Type: 241, Value: []byte{8, 'y'}},
		extMore(245, 1, 'a'),
		extLong(245, 1, 0, 'b'),
	)
	if v, ok := d.GetExtended(p, "", "Frag-Status"); !ok || !bytes.Equal(v, []byte{0, 0, 0, 2}) {
		t.Errorf("Frag-Status = %v, %v", v, ok)
	}
	if v, ok := d.GetExtended(p, "", "Ext-Name"); !ok || string(v) != "x" {
		t.Errorf("Ext-Name = %q, %v (want the first)", v, ok)
	}
	if v, ok := d.GetExtended(p, "", "Long-Blob"); !ok || string(v) != strings.Repeat("a", maxLongExtData)+"b" {
		t.Errorf("Long-Blob = %q, %v", v, ok)
	}
	if _, ok := d.GetExtended(p, "", "Long-Text"); ok {
		t.Error("Long-Text found")
	}
	if _, ok := d.GetExtended(p, "", "Nope"); ok {
		t.Error("Nope found")
	}
}

// Broken fragment chains and truncated headers are skipped, never joined.
func TestGetExtendedMalformed(t *testing.T) {
	d := loadExtTestDict(t)
	tests := []struct {
		name string
		avps []AVP
	}{
		{"More on last AVP", []AVP{extMore(245, 1, 'a')}},
		{"short More fragment", []AVP{extLong(245, 1, extMoreFlag, 'a'), extLong(245, 1, 0, 'b')}},
		{"interrupted", []AVP{extLong(245, 1, extMoreFlag, 'a'), {Type: AttrUserName, Value: []byte("u")}}},
		{"other ext type", []AVP{extLong(245, 1, extMoreFlag, 'a'), extLong(245, 2, 0, 'b')}},
		{"other outer type", []AVP{extLong(245, 1, extMoreFlag, 'a'), {Type: 246, Value: []byte{1, 0, 'b'}}}},
		{"truncated next", []AVP{extLong(245, 1, extMoreFlag, 'a'), {Type: 245, Value: []byte{1}}}},
		{"no flags", []AVP{{Type: 245, Value: []byte{1}}}},
		{"empty", []AVP{{Type: 245}, {Type: 241}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Request(AccessRequest, "secret")
			p.AddAVP(tt.avps...)
			if v, ok := d.GetExtended(p, "", "Long-Blob"); ok {
				t.Errorf("GetExtended = %q", v)
			}
			p.EachAVP(func(a AVP) bool {
				_ = d.DecodeAVPValue(p, a)
				return true
			})
		})
	}
	// a broken chain doesn't hide a later good value
	p := Request(AccessRequest, "secret")
	p.AddAVP(extLong(245, 1, extMoreFlag, 'a'), extLong(245, 2, 0, 'z'), extLong(245, 1, 0, 'b'))
	if v, ok := d.GetExtended(p, "", "Long-Blob"); !ok || string(v) != "b" {
		t.Errorf("after broken chain = %q, %v", v, ok)
	}
	// truncated EVS header
	p = Request(AccessRequest, "secret")
	p.AddAVP(AVP{Type: 241, Value: []byte{26, 0, 0, 0x2c}})
	if _, ok := d.GetExtended(p, "ExtVendor", "EV1-Id"); ok {
		t.Error("EV1-Id found in truncated EVS")
	}
}

func TestExtendedDecodeAVPValue(t *testing.T) {
	d := useExtDefault(t)
	tests := []struct {
		avp  AVP
		want string
	}{
		{AVP{Type: 241, Value: []byte{1, 0, 0, 0, 2}}, "{Attr: Frag-Status #241.1, Value: More-Data-Pending}"},
		{AVP{Type: 241, Value: []byte{8, 'h', 'i'}}, "{Attr: Ext-Name #241.8, Value: hi}"},
		{AVP{Type: 241, Value: []byte{5, 1, 6, 0, 0, 0, 1}}, "{Attr: Ext-Port-Info #241.5, Value: {Ext-Port-Type: Static}}"},
		{AVP{Type: 241, Value: []byte{99, 7}}, `{Attr: #241.99, Value: []byte{0x7}}`},
		{extLong(245, 2, 0, 'o', 'k'), "{Attr: Long-Text #245.2, Value: ok}"},
		{extLong(245, 2, extMoreFlag, 'o', 'k'), "{Attr: Long-Text #245.2, More, Value: ok}"},
		{extLong(245, 26, 0, 0, 0, 0x2c, 0x50, 2, 0, 0, 0, 2), "{Vendor:ExtVendor #11344, Attr: EV-Count #245.26.11344.2, Value: Two}"},
		{extLong(245, 26, 0, 0, 0, 0, 9, 2, 1), `{Vendor: 9, Attr: #245.26.9.2, Value: []byte{0x1}}`},
		{AVP{Type: 241}, "[]byte(nil)"},
		{AVP{Type: 245, Value: []byte{1}}, "[]byte{0x1}"},
		{AVP{Type: 241, Value: []byte{26, 0, 0}}, "[]byte{0x1a, 0x0, 0x0}"},
	}
	for _, tt := range tests {
		if got := d.DecodeAVPValue(nil, tt.avp); got != tt.want {
			t.Errorf("DecodeAVPValue(%v) = %s, want %s", tt.avp.Value, got, tt.want)
		}
	}
	a := AVP{Type: 241, Value: []byte{1, 0, 0, 0, 2}}
	if got, want := a.String(), "AVP type: Extended-Attribute-1 {Attr: Frag-Status #241.1, Value: More-Data-Pending}"; got != want {
		t.Errorf("String = %s, want %s", got, want)
	}
}

func TestExtendedTLV(t *testing.T) {
	d := loadExtTestDict(t)
	avp, err := buildTLV(d, "", "Ext-Port-Info",
		tlvValue{Name: "Ext-Port-Type", Value: "Static"},
		tlvValue{Name: "Ext-Port-Addr", Value: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{5, 1, 6, 0, 0, 0, 1, 3, 6, 10, 0, 0, 1}
	if avp.Type != 241 || !bytes.Equal(avp.Value, want) {
		t.Errorf("ParseTLV = %v, want 241 %v", avp, want)
	}
	avp, err = buildTLV(d, "", "Long-TLV", tlvValue{Name: "Long-TLV-Id", Value: "7"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{3, 0, 1, 6, 0, 0, 0, 7}; avp.Type != 245 || !bytes.Equal(avp.Value, want) {
		t.Errorf("ParseTLV long = %v, want 245 %v", avp, want)
	}

	p := Request(AccessRequest, "secret")
	p.AddAVP(AVP{Type: 241, Value: []byte{5, 1, 6, 0, 0, 0, 1}})
	// a TLV split over two long-extended fragments, after an unknown one filling the first
	pad := append([]byte{99, maxLongExtData - 3}, make([]byte, maxLongExtData-5)...)
	p.AddAVP(extLong(245, 3, extMoreFlag, append(pad, 1, 6, 0)...), extLong(245, 3, 0, 0, 0, 9))
	if s, ok := d.GetTLVString(p, "", "Ext-Port-Type"); !ok || s != "Static" {
		t.Errorf("GetTLVString = %q, %v", s, ok)
	}
	if v, ok := d.GetTLV(p, "", "Long-TLV-Id"); !ok || !bytes.Equal(v, []byte{0, 0, 0, 9}) {
		t.Errorf("GetTLV long = %v, %v", v, ok)
	}
}

func TestExtendedTemplates(t *testing.T) {
	d := loadExtTestDict(t)
	rt, err := d.CreateRequestTemplate(AccessRequest, "Frag-Status", "Long-Text")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.AddVSAAttribute(d, "ExtVendor", "EV-Count"); err != nil {
		t.Fatal(err)
	}
	p := Request(AccessRequest, "secret")
	long := strings.Repeat("x", 300)
	rt.Fill(p, "More-Data-Pending", long, "Two")
	if len(p.AVPs) != 4 {
		t.Fatalf("AVPs = %v", p.AVPs)
	}
	if v, ok := d.GetExtended(p, "", "Frag-Status"); !ok || !bytes.Equal(v, []byte{0, 0, 0, 2}) {
		t.Errorf("Frag-Status = %v, %v", v, ok)
	}
	if v, ok := d.GetExtended(p, "", "Long-Text"); !ok || string(v) != long {
		t.Errorf("Long-Text = %d bytes, %v", len(v), ok)
	}
	if v, ok := d.GetExtended(p, "ExtVendor", "EV-Count"); !ok || !bytes.Equal(v, []byte{0, 0, 0, 2}) {
		t.Errorf("EV-Count = %v, %v", v, ok)
	}
	if _, err := d.GetTemplate("Frag-Status:1"); !errors.Is(err, ErrInvalidTag) {
		t.Errorf("tagged template: err = %v", err)
	}
}

func TestExtendedDictionaryErrors(t *testing.T) {
	const base = "ATTRIBUTE E 241 extended\nATTRIBUTE L 245 long-extended\nATTRIBUTE EVS 241.26 evs\nATTRIBUTE X 241.1 integer\nATTRIBUTE U 1 string\n"
	tests := []struct{ name, dict string }{
		{"ext redeclared with another number", "ATTRIBUTE X 241.2 integer"},
		{"ext redeclared with another type", "ATTRIBUTE X 241.1 string"},
		{"ext redeclared under another parent", "ATTRIBUTE X 245.1 integer"},
		{"top-level redeclared as ext", "ATTRIBUTE U 241.3 string"},
		{"ext redeclared as top-level", "ATTRIBUTE X 7 integer"},
		{"evs not at 26", "ATTRIBUTE EVS2 241.27 evs"},
		{"26 not evs", "ATTRIBUTE L-26 245.26 integer"},
		{"BEGIN-VENDOR format unknown", "VENDOR V 9\nBEGIN-VENDOR V format=Nope"},
		{"BEGIN-VENDOR format not evs", "VENDOR V 9\nBEGIN-VENDOR V format=X"},
		{"BEGIN-VENDOR bad option", "VENDOR V 9\nBEGIN-VENDOR V foo=EVS"},
		{"EVS name taken by VSA", "VENDOR V 9\nBEGIN-VENDOR V\nATTRIBUTE V-1 1 string\nEND-VENDOR V\nBEGIN-VENDOR V format=EVS\nATTRIBUTE V-1 1 string"},
		{"EVS name redeclared as VSA", "VENDOR V 9\nBEGIN-VENDOR V format=EVS\nATTRIBUTE V-1 1 string\nEND-VENDOR V\nBEGIN-VENDOR V\nATTRIBUTE V-1 1 string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewDictionary().loadReader("bad", strings.NewReader(base+tt.dict))
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestExtendedRedeclareAndAlias(t *testing.T) {
	d := loadTLVDict(t, `
ATTRIBUTE E 241 extended
ATTRIBUTE X 241.1 integer
ATTRIBUTE X 241.1 integer
ATTRIBUTE Y 241.1 integer
VALUE X One 1
VALUE Y Uno 1
`)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	a := AVP{Type: 241, Value: []byte{1, 0, 0, 0, 1}}
	if got := d.DecodeAVPValue(nil, a); got != "{Attr: Y #241.1, Value: Uno}" {
		t.Errorf("alias decodes as %s", got)
	}
	for _, name := range []string{"X", "Y"} {
		if avp, err := d.ParseAVP(name, "1"); err != nil || avp.Type != 241 {
			t.Errorf("%s: %v, %v", name, avp, err)
		}
	}
	if err := NewDictionary().loadReader("bad", strings.NewReader("ATTRIBUTE E 241 extended\nATTRIBUTE X 241.1 integer\nATTRIBUTE X 241.1 date")); err == nil {
		t.Error("extended redeclared with another type: expected error")
	}
	// TLV children of an extended attribute stay unique against extended names
	if err := NewDictionary().loadReader("bad", strings.NewReader("ATTRIBUTE E 241 extended\nATTRIBUTE T 241.2 tlv\nATTRIBUTE X 241.2.1 integer\nATTRIBUTE X 241.3 integer")); err == nil {
		t.Error("child redeclared as extended: expected error")
	}
}

// Sub-attributes of Extended-Vendor-Specific given as dotted ids are skipped quietly.
func TestExtendedEVSDottedSkipped(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, `
ATTRIBUTE E 241 extended
ATTRIBUTE EVS 241.26 evs
ATTRIBUTE V-1 241.26.9.1 integer
VALUE V-1 One 1
ATTRIBUTE V-2 241.26.11344.9 integer
VALUE V-2 Two 2
`)
	if _, err := d.ParseExtended("", "V-1", "1"); err == nil {
		t.Error("V-1 loaded")
	}
	if n := h.count(slog.LevelWarn, ""); n != 0 {
		t.Errorf("warnings:\n%s", h.all())
	}
}

func TestExtendedBuiltin(t *testing.T) {
	d := NewDictionary()
	if err := d.LoadBuiltin(); err != nil {
		t.Fatal(err)
	}
	for typ, name := range map[AttributeType]string{AttrExtendedType1: "Extended-Attribute-1", AttrLongExtendedType2: "Extended-Attribute-6"} {
		if got := d.GetAttributeName(typ); got != name {
			t.Errorf("%d = %q, want %q", typ, got, name)
		}
	}
	// FreeRADIUS definitions load on top of the builtin ones
	if err := d.loadReader("rfc", strings.NewReader(extTestDict)); err != nil {
		t.Fatal(err)
	}
}

func FuzzExtendedDecode(f *testing.F) {
	d := loadExtTestDict(f)
	f.Add([]byte{1, 0, 0, 0, 2}, []byte{})
	f.Add([]byte{26, 0, 0, 0, 0x2c, 0x50, 2, 0, 0, 0, 2}, []byte{})
	f.Add([]byte{3, extMoreFlag, 1, 6, 0}, []byte{3, 0, 0, 0, 1})
	f.Add([]byte{5, 1, 6, 0, 0, 0, 1}, []byte{})
	f.Add([]byte{1, extMoreFlag, 'a'}, []byte{1, 0, 'b'})
	f.Add([]byte{1, 0x7f, 'x'}, []byte{1, 0xff, 'y'})
	f.Add([]byte{26, extMoreFlag, 0, 0, 0x2c, 0x50, 1, 0xab}, []byte{26, 0, 0xab, 0xab})
	f.Add([]byte{26, 0, 0, 0, 0x2c, 0x50, 3, 1, 6, 0, 0, 0, 7}, []byte{3, 0, 1, 6, 0, 0, 0, 7})
	f.Fuzz(func(t *testing.T, value, next []byte) {
		if len(value) > maxAVPValueLen || len(next) > maxAVPValueLen {
			return
		}
		p := Request(AccessRequest, "secret")
		for _, typ := range []AttributeType{241, 245, 246} {
			p.AddAVP(AVP{Type: typ, Value: value}, AVP{Type: typ, Value: next})
		}
		for _, a := range p.AVPs {
			_ = d.DecodeAVPValue(p, a)
		}
		_ = p.String()
		for _, c := range [][2]string{{"", "Frag-Status"}, {"", "Long-Blob"}, {"", "Long6-Blob"}, {"", "Long-TLV"}, {"ExtVendor", "EV-Anonce"}, {"ExtVendor", "EV1-Id"}} {
			d.GetExtended(p, c[0], c[1])
		}
		d.GetTLVString(p, "", "Ext-Port-Type")
		d.GetTLV(p, "", "Long-TLV-Id")
		d.GetTLVString(p, "ExtVendor", "EV-T-Id")
	})
}

// Continuation fragments are marked and keep the attribute of the first one, also for EVS.
func TestExtendedContinuationString(t *testing.T) {
	d := useExtDefault(t)
	p := Request(AccessRequest, "secret")
	p.AddExtended(ExtendedAttr{Type: 245, ExtType: ExtTypeEVS, Vendor: testExtVendorID, VendorType: 1, Value: bytes.Repeat([]byte{0xab}, 600)})
	p.AddExtended(ExtendedAttr{Type: 245, ExtType: 1, Value: bytes.Repeat([]byte{0xcd}, 300)})
	if len(p.AVPs) != 5 {
		t.Fatalf("got %d AVPs, want 5", len(p.AVPs))
	}
	wants := []string{
		"{Vendor:ExtVendor #11344, Attr: EV-Anonce #245.26.11344.1, More, Value: []byte{0xab",
		"{Vendor:ExtVendor #11344, Attr: EV-Anonce #245.26.11344.1, Continued, More, Value: []byte{0xab",
		"{Vendor:ExtVendor #11344, Attr: EV-Anonce #245.26.11344.1, Continued, Value: []byte{0xab",
		"{Attr: Long-Blob #245.1, More, Value: []byte{0xcd",
		"{Attr: Long-Blob #245.1, Continued, Value: []byte{0xcd",
	}
	for i, want := range wants {
		if got := d.DecodeAVPValue(p, p.AVPs[i]); !strings.HasPrefix(got, want) {
			t.Errorf("fragment %d = %.90q, want prefix %q", i, got, want)
		}
	}
	if s := p.String(); strings.Count(s, "Continued") != 3 || strings.Contains(s, "Vendor: ") {
		t.Errorf("Packet.String =\n%s", s)
	}
}

// Long follows from Type; other types and the zero ExtendedAttr aren't encoded.
func TestExtendedAttrType(t *testing.T) {
	useRecordLogger(t)
	tests := []struct {
		e    ExtendedAttr
		want []byte
	}{
		{ExtendedAttr{Type: 245, ExtType: 1, Value: []byte("abc")}, []byte{1, 0, 'a', 'b', 'c'}},
		{ExtendedAttr{Type: 246, ExtType: 1, Value: []byte("abc")}, []byte{1, 0, 'a', 'b', 'c'}},
		{ExtendedAttr{Type: 241, ExtType: 1, Value: []byte("abc")}, []byte{1, 'a', 'b', 'c'}},
		{ExtendedAttr{Type: 244, ExtType: 1, Value: []byte("abc")}, []byte{1, 'a', 'b', 'c'}},
	}
	for _, tt := range tests {
		if avps := tt.e.ToAVPList(); len(avps) != 1 || avps[0].Type != tt.e.Type || !bytes.Equal(avps[0].Value, tt.want) {
			t.Errorf("%d: ToAVPList = %v, want %v", tt.e.Type, avps, tt.want)
		}
	}
	for _, e := range []ExtendedAttr{{}, {Type: 26, ExtType: 1, Value: []byte{1}}, {Type: 247, ExtType: 1, Value: []byte{1}}} {
		if avps := e.ToAVPList(); avps != nil {
			t.Errorf("%+v: ToAVPList = %v, want nil", e, avps)
		}
		p := Request(AccessRequest, "secret")
		p.AddExtended(e)
		if len(p.AVPs) != 0 {
			t.Errorf("%+v: AddExtended added %v", e, p.AVPs)
		}
	}
}

// RFC 6929 requires a non-empty value and a Vendor-Id with a zero high octet.
func TestExtendedMinimumLength(t *testing.T) {
	useRecordLogger(t)
	d := loadExtTestDict(t)
	if _, err := d.ParseAVP("Ext-Name", ""); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseAVP empty: err = %v", err)
	}
	for _, c := range [][2]string{{"", "Long-Text"}, {"ExtVendor", "EV-Anonce"}} {
		if _, err := d.ParseExtended(c[0], c[1], ""); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseExtended %s empty: err = %v", c[1], err)
		}
	}
	for _, e := range []ExtendedAttr{
		{Type: 241, ExtType: 8},
		{Type: 245, ExtType: 2},
		{Type: 245, ExtType: ExtTypeEVS, Vendor: testExtVendorID, VendorType: 1},
		{Type: 241, ExtType: ExtTypeEVS, Vendor: 1 << 24, VendorType: 1, Value: []byte{1}},
	} {
		if avps := e.ToAVPList(); avps != nil {
			t.Errorf("%+v: ToAVPList = %v, want nil", e, avps)
		}
	}

	raw := func(a AVP) string { return avpBinary.String(nil, a) }
	for _, a := range []AVP{
		{Type: 241, Value: []byte{1}},
		{Type: 245, Value: []byte{2, 0}},
		{Type: 241, Value: []byte{26, 0, 0, 0x2c, 0x50, 3}},
		{Type: 241, Value: []byte{26, 1, 0, 0x2c, 0x50, 3, 0, 0, 0, 1}},
	} {
		if got := d.DecodeAVPValue(nil, a); got != raw(a) {
			t.Errorf("%v = %q, want raw", a, got)
		}
	}
	p := &Packet{AVPs: []AVP{{Type: 245, Value: []byte{2, 0}}}}
	if v, ok := d.GetExtended(p, "", "Long-Text"); ok {
		t.Errorf("GetExtended empty = %v", v)
	}
}

// An EVS attribute of vendor 0 has no name.
func TestExtendedEVSVendorZero(t *testing.T) {
	d := loadExtTestDict(t)
	a := AVP{Type: 241, Value: []byte{26, 0, 0, 0, 0, 1, 0, 0, 0, 2}}
	if got := d.DecodeAVPValue(nil, a); strings.Contains(got, "Frag-Status") {
		t.Errorf("DecodeAVPValue = %q", got)
	}
}

// TLVs in an Extended-Vendor-Specific block.
func TestExtendedEVSTLV(t *testing.T) {
	d := loadExtTestDict(t)
	avp, err := buildTLV(d, "ExtVendor", "EV-T", tlvValue{Name: "EV-T-Id", Value: "7"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{26, 0, 0, 0, 0x2c, 0x50, 3, 1, 6, 0, 0, 0, 7}; avp.Type != 245 || !bytes.Equal(avp.Value, want) {
		t.Errorf("ParseTLV = %d %v, want 245 %v", avp.Type, avp.Value, want)
	}
	p := &Packet{AVPs: []AVP{avp}}
	if s, ok := d.GetTLVString(p, "ExtVendor", "EV-T-Id"); !ok || s != "7" {
		t.Errorf("GetTLVString = %q, %v", s, ok)
	}
	if got := d.DecodeAVPValue(p, avp); got != "{Vendor:ExtVendor #11344, Attr: EV-T #245.26.11344.3, Value: {EV-T-Id: 7}}" {
		t.Errorf("DecodeAVPValue = %q", got)
	}
}

// A non-long extended TLV too long for one attribute is an error, not a warning.
func TestExtendedTLVTooLong(t *testing.T) {
	h := useRecordLogger(t)
	d := loadExtTestDict(t)
	values := make([]tlvValue, 43) // 258 bytes
	for i := range values {
		values[i] = tlvValue{Name: "Ext-Port-Type", Value: "1"}
	}
	if _, err := buildTLV(d, "", "Ext-Port-Info", values...); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("err = %v", err)
	}
	if n := h.count(slog.LevelWarn, ""); n != 0 {
		t.Errorf("warnings:\n%s", h.all())
	}
}

// Extended attributes of the library's encrypted types are refused when the template is made.
func TestExtendedEncryptedTypes(t *testing.T) {
	d := loadTLVDict(t, "ATTRIBUTE E 241 extended\nATTRIBUTE E-P 241.1 password\nATTRIBUTE E-T 241.2 tunnel-password\n")
	for _, name := range []string{"E-P", "E-T"} {
		if _, err := d.GetTemplate(name); !errors.Is(err, ErrUnsupportedAttributeType) {
			t.Errorf("GetTemplate %s: err = %v", name, err)
		}
		if _, err := d.ParseExtended("", name, "x"); !errors.Is(err, ErrUnsupportedAttributeType) {
			t.Errorf("ParseExtended %s: err = %v", name, err)
		}
	}
}
