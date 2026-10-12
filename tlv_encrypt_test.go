package radius

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const encTLVDict = `
ATTRIBUTE	Vendor-Specific	26	vsa
ATTRIBUTE	Tunnel-Password	69	string	has_tag,encrypt=2
ATTRIBUTE	Enc-TLV		200	tlv
ATTRIBUTE	Enc-Pass	200.1	string	encrypt=1
ATTRIBUTE	Enc-Key		200.2	string	encrypt=2
ATTRIBUTE	Enc-Num		200.3	integer
ATTRIBUTE	Enc-Int		200.4	integer	encrypt=2
ATTRIBUTE	Enc-Secret	200.5	string	encrypt=3
ATTRIBUTE	Enc-Nest	200.6	tlv
ATTRIBUTE	Enc-Nest-Key	200.6.1	octets	encrypt=2

ATTRIBUTE	Extended-Attribute-1	241	extended
ATTRIBUTE	Extended-Attribute-5	245	long-extended
ATTRIBUTE	Ext-Enc		241.7	tlv
ATTRIBUTE	Ext-Enc-Pass	241.7.1	string	encrypt=1
ATTRIBUTE	Ext-Enc-Key	241.7.2	string	encrypt=2
ATTRIBUTE	Long-Enc	245.7	tlv
ATTRIBUTE	Long-Enc-Blob	245.7.1	octets
ATTRIBUTE	Long-Enc-Key	245.7.2	string	encrypt=2
ATTRIBUTE	Long-Enc-Pass	245.7.3	string	encrypt=1

VENDOR		WiMAX		24757	format=1,1,c
BEGIN-VENDOR	WiMAX
ATTRIBUTE	WiMAX-hDHCP-Server-Parameters	86	tlv
ATTRIBUTE	WiMAX-hDHCP-DHCP-RK		86.3	string	encrypt=2
ATTRIBUTE	WiMAX-hDHCP-DHCP-RK-Key-Id	86.4	integer
END-VENDOR	WiMAX
`

const (
	encTLVType    = 200
	encTLVSecret  = "testing123"
	userPassChild = "fe9b67be118f481a104607240014828b" // "hunter2", encrypt=1, authenticator 00..0f
	// "tunnel-pass", salt 0x8123, encrypt=2 without a tag byte, authenticator 00..0f
	tunnelPassChild = "812379529da6b23e3aa2fbb16e08eeba8f83"
)

// encTLVVectorPacket returns an Access-Accept to a request with authenticator 00..0f holding both test vectors.
func encTLVVectorPacket(t testing.TB) (*Packet, AVP) {
	t.Helper()
	pass, _ := hex.DecodeString(userPassChild)
	key, _ := hex.DecodeString(tunnelPassChild)
	var v []byte
	v = append(v, 1, byte(tlvHeaderLen+len(pass)))
	v = append(v, pass...)
	v = append(v, 2, byte(tlvHeaderLen+len(key)))
	v = append(v, key...)
	p := &Packet{Secret: encTLVSecret, Code: AccessAccept}
	for i := range p.requestAuth {
		p.requestAuth[i] = byte(i)
	}
	a := AVP{Type: encTLVType, Value: v}
	p.AddAVP(a)
	return p, a
}

// Encrypted sub-attributes are hidden exactly like top-level ones (FreeRADIUS), without a tag byte.
func TestTLVEncryptVector(t *testing.T) {
	auth := make([]byte, authenticatorLen)
	for i := range auth {
		auth[i] = byte(i)
	}
	got, err := encryptValueSalt(encryptUserPassword, []byte("hunter2"), encTLVSecret, auth, [tunnelSaltLen]byte{})
	if err != nil || hex.EncodeToString(got) != userPassChild {
		t.Errorf("encrypt=1: %x, %v; want %s", got, err, userPassChild)
	}
	salt := [tunnelSaltLen]byte{0x81, 0x23}
	got, err = encryptValueSalt(encryptTunnelPassword, []byte("tunnel-pass"), encTLVSecret, auth, salt)
	if err != nil || hex.EncodeToString(got) != tunnelPassChild {
		t.Errorf("encrypt=2: %x, %v; want %s", got, err, tunnelPassChild)
	}
	// same as a top-level Tunnel-Password without its tag
	if top := tunnelPasswordEncrypt(0, salt, "tunnel-pass", encTLVSecret, auth); !bytes.Equal(got, top[tunnelTagLen:]) {
		t.Errorf("encrypt=2 = %x, top-level = %x", got, top)
	}
}

// GetTLV, GetTLVString and DecodeAVPValue decrypt with the packet; without one they show octets.
func TestTLVDecryptVector(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	p, a := encTLVVectorPacket(t)
	for name, want := range map[string]string{"Enc-Pass": "hunter2", "Enc-Key": "tunnel-pass"} {
		if v, ok := d.GetTLV(p, "", name); !ok || string(v) != want {
			t.Errorf("GetTLV %s = %q, %v; want %q", name, v, ok, want)
		}
		if s, ok := d.GetTLVString(p, "", name); !ok || s != want {
			t.Errorf("GetTLVString %s = %q, %v; want %q", name, s, ok, want)
		}
	}
	if got, want := d.DecodeAVPValue(p, a), "{Enc-Pass: hunter2, Enc-Key: tunnel-pass}"; got != want {
		t.Errorf("DecodeAVPValue = %q, want %q", got, want)
	}
	got := d.DecodeAVPValue(nil, a)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "tunnel-pass") || !strings.Contains(got, "Enc-Pass: []byte{") {
		t.Errorf("DecodeAVPValue(nil) = %q, want octets", got)
	}
}

// AddTLV encrypts in replies with the request authenticator; the peer decrypts them.
func TestAddTLVReplyRoundTrip(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	key := strings.Repeat("k", 32)
	req := Request(AccessRequest, encTLVSecret)
	reply := req.ReplyAccept()
	err := d.AddTLV(reply, "", "Enc-TLV",
		TLVValue{Name: "Enc-Pass", Value: "hunter2"},
		TLVValue{Name: "Enc-Key", Value: "tunnel-pass"},
		TLVValue{Name: "Enc-Num", Value: "5"},
		TLVValue{Name: "Enc-Int", Value: "7"},
		TLVValue{Name: "Enc-Nest-Key", Value: key},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddTLV(reply, "WiMAX", "WiMAX-hDHCP-Server-Parameters",
		TLVValue{Name: "WiMAX-hDHCP-DHCP-RK", Value: key},
		TLVValue{Name: "WiMAX-hDHCP-DHCP-RK-Key-Id", Value: "1"},
	); err != nil {
		t.Fatal(err)
	}
	for _, a := range reply.AVPs {
		if bytes.Contains(a.Value, []byte("hunter2")) || bytes.Contains(a.Value, []byte("tunnel-pass")) || bytes.Contains(a.Value, []byte(key)) {
			t.Fatalf("plaintext on the wire: %x", a.Value)
		}
	}
	raw, ok := findTLV(reply.AVPs[0].Value, []uint8{2})
	if !ok || raw[0]&tunnelSaltBit == 0 {
		t.Errorf("Enc-Key salt = %x, want high bit set", raw)
	}

	b, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeReply(encTLVSecret, b, req.Authenticator[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ vendor, name, want string }{
		{"", "Enc-Pass", "hunter2"},
		{"", "Enc-Key", "tunnel-pass"},
		{"", "Enc-Num", "5"},
		{"", "Enc-Int", "7"},
		{"WiMAX", "WiMAX-hDHCP-DHCP-RK", key},
		{"WiMAX", "WiMAX-hDHCP-DHCP-RK-Key-Id", "1"},
	} {
		if s, ok := d.GetTLVString(got, c.vendor, c.name); !ok || s != c.want {
			t.Errorf("%s = %q, %v; want %q", c.name, s, ok, c.want)
		}
	}
	if v, ok := d.GetTLV(got, "", "Enc-Int"); !ok || !bytes.Equal(v, []byte{0, 0, 0, 7}) {
		t.Errorf("GetTLV Enc-Int = %v, %v", v, ok)
	}
	if v, ok := d.GetTLV(got, "", "Enc-Nest-Key"); !ok || string(v) != key {
		t.Errorf("GetTLV Enc-Nest-Key = %q, %v", v, ok)
	}

	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	if s := got.String(); !strings.Contains(s, "Enc-Pass: hunter2") || !strings.Contains(s, "WiMAX-hDHCP-DHCP-RK: "+key) {
		t.Errorf("Packet.String = %q, want decrypted values", s)
	}
}

// An Access-Request hides encrypt=1 values with its own authenticator, generated if it isn't set.
func TestAddTLVRequestAuthenticator(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	packets := map[string]*Packet{
		"Request": Request(AccessRequest, encTLVSecret),
		"manual":  {Code: AccessRequest, Secret: encTLVSecret},
	}
	for which, p := range packets {
		if err := d.AddTLV(p, "", "Enc-TLV", TLVValue{Name: "Enc-Pass", Value: "hunter2"}); err != nil {
			t.Fatal(err)
		}
		if p.Authenticator == zeroAuthenticator {
			t.Errorf("%s: authenticator not generated", which)
		}
		pass, _ := findTLV(p.AVPs[0].Value, []uint8{1})
		if want := avpPassword.Encode("hunter2", encTLVSecret, p.Authenticator[:]); !bytes.Equal(pass, want) {
			t.Errorf("%s: Enc-Pass = %x, want %x", which, pass, want)
		}
	}
}

// ParseTLV can't encrypt, so it refuses encrypted sub-attributes and points to AddTLV.
func TestParseTLVEncryptedRefused(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	for _, name := range []string{"Enc-Pass", "Enc-Key", "Enc-Nest-Key"} {
		_, err := d.ParseTLV("", "Enc-TLV", TLVValue{Name: name, Value: "pw"})
		if !errors.Is(err, ErrEncryptedAttribute) || !strings.Contains(err.Error(), "AddTLV") {
			t.Errorf("ParseTLV %s: err = %v", name, err)
		}
	}
	if err := d.AddTLV(nil, "", "Enc-TLV", TLVValue{Name: "Enc-Key", Value: "pw"}); !errors.Is(err, ErrNilPacket) {
		t.Errorf("AddTLV(nil): err = %v", err)
	}
}

// Unsupported methods and over-long values are errors; nothing is added.
func TestAddTLVErrors(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	p := Request(AccessRequest, encTLVSecret).ReplyAccept()
	cases := []struct {
		vendor, attr, name, value string
		want                      error
	}{
		{"", "Enc-TLV", "Enc-Secret", "x", ErrUnsupportedAttributeType},
		{"", "Enc-TLV", "Enc-Pass", strings.Repeat("p", maxPasswordLen+1), ErrInvalidValue},
		{"", "Enc-TLV", "Enc-Key", strings.Repeat("k", 240), ErrInvalidValue},
		{"", "Enc-TLV", "Enc-Int", "x", ErrInvalidValue},
		{"", "Enc-TLV", "Nope", "x", ErrUnknownAttribute},
		{"WiMAX", "WiMAX-hDHCP-Server-Parameters", "WiMAX-hDHCP-DHCP-RK", strings.Repeat("k", wimaxFragmentData), ErrInvalidValue},
	}
	for _, c := range cases {
		if err := d.AddTLV(p, c.vendor, c.attr, TLVValue{Name: c.name, Value: c.value}); !errors.Is(err, c.want) {
			t.Errorf("AddTLV %s (%d bytes): err = %v, want %v", c.name, len(c.value), err, c.want)
		}
	}
	if len(p.AVPs) != 0 {
		t.Errorf("AVPs added on error: %d", len(p.AVPs))
	}
	for _, v := range []string{"", strings.Repeat("p", maxPasswordLen)} {
		if err := d.AddTLV(p, "", "Enc-TLV", TLVValue{Name: "Enc-Pass", Value: v}); err != nil {
			t.Errorf("Enc-Pass %d bytes: %v", len(v), err)
		}
	}
	if err := d.AddTLV(p, "", "Enc-TLV", TLVValue{Name: "Enc-Key", Value: strings.Repeat("k", 239)}); err != nil {
		t.Errorf("Enc-Key 239 bytes: %v", err)
	}
}

// Malformed ciphertext is not found by GetTLV and shown as octets.
func TestTLVDecryptMalformed(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	vp, _ := encTLVVectorPacket(t)
	// an empty password whose hidden length byte is flipped to 0xff
	long := tunnelPasswordEncrypt(0, [tunnelSaltLen]byte{0x81, 0x23}, "", encTLVSecret, vp.requestAuth[:])[tunnelTagLen:]
	long[tunnelSaltLen] ^= 0xff
	for _, c := range []struct {
		name string
		v    []byte
	}{
		{"Enc-Pass", []byte{1, 2}},                                                   // empty encrypt=1
		{"Enc-Pass", []byte{1, 5, 1, 2, 3}},                                          // not a block multiple
		{"Enc-Key", []byte{2, 4, 0x81, 0x23}},                                        // salt only
		{"Enc-Key", []byte{2, 19, 0x81, 0x23, 1, 2}},                                 // malformed TLV
		{"Enc-Key", append([]byte{2, byte(tlvHeaderLen + len(long))}, long...)},      // length byte too large
		{"Enc-Secret", append([]byte{5, 18}, bytes.Repeat([]byte{1}, blockSize)...)}, // encrypt=3 isn't decrypted
	} {
		p := &Packet{Secret: encTLVSecret, Code: AccessAccept, requestAuth: vp.requestAuth}
		a := AVP{Type: encTLVType, Value: c.v}
		p.AddAVP(a)
		if got, ok := d.GetTLV(p, "", c.name); ok {
			t.Errorf("%x: GetTLV %s = %q, want not found", c.v, c.name, got)
		}
		if got := d.DecodeAVPValue(p, a); !strings.Contains(got, "[]byte{") {
			t.Errorf("%x: DecodeAVPValue = %q, want octets", c.v, got)
		}
	}
}

// An encrypted "tlv" sub-attribute (not supported) can't be built and its children aren't read.
func TestTLVEncryptedContainer(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, "ATTRIBUTE A 200 tlv\nATTRIBUTE A-C 200.1 tlv encrypt=2\nATTRIBUTE A-C-X 200.1.1 integer\n")
	if !strings.Contains(h.all(), "not supported") {
		t.Errorf("no warning:\n%s", h.all())
	}
	reply := Request(AccessRequest, encTLVSecret).ReplyAccept()
	// the error names the encrypted TLV
	wantErr := map[string]string{"A-C-X": "A-C-X: parent A-C is encrypted", "A-C": "A-C is encrypted"}
	for _, v := range []TLVValue{{Name: "A-C-X", Value: "1"}, {Name: "A-C"}} {
		if _, err := d.ParseTLV("", "A", v); !errors.Is(err, ErrUnsupportedAttributeType) || !strings.Contains(err.Error(), wantErr[v.Name]) {
			t.Errorf("ParseTLV %s: err = %v, want %q", v.Name, err, wantErr[v.Name])
		}
		if err := d.AddTLV(reply, "", "A", v); !errors.Is(err, ErrUnsupportedAttributeType) {
			t.Errorf("AddTLV %s: err = %v", v.Name, err)
		}
	}
	if len(reply.AVPs) != 0 {
		t.Errorf("AVPs added: %v", reply.AVPs)
	}
	inner := []byte{1, 6, 0, 0, 0, 1}
	a := AVP{Type: encTLVType, Value: append([]byte{1, byte(tlvHeaderLen + len(inner))}, inner...)}
	reply.AddAVP(a)
	if v, ok := d.GetTLV(reply, "", "A-C-X"); ok {
		t.Errorf("GetTLV A-C-X = %x, want not found", v)
	}
	if got, want := d.DecodeAVPValue(reply, a), "{A-C: "+avpBinary.String(nil, AVP{Value: inner})+"}"; got != want {
		t.Errorf("DecodeAVPValue = %q, want %q", got, want)
	}
}

// encrypt=1 is supported only on strings: such values are never built, nor decrypted.
func TestTLVEncryptNonString(t *testing.T) {
	h := useRecordLogger(t)
	d := loadTLVDict(t, "ATTRIBUTE R 200 tlv\nATTRIBUTE R-Int1 200.1 integer encrypt=1\nATTRIBUTE R-Oct1 200.2 octets encrypt=1\nATTRIBUTE R-Str1 200.3 string encrypt=1\nATTRIBUTE R-Int2 200.4 integer encrypt=2\n")
	if !strings.Contains(h.all(), "not supported") || !strings.Contains(h.all(), "R-Oct1") {
		t.Errorf("no warning:\n%s", h.all())
	}
	reply := Request(AccessRequest, encTLVSecret).ReplyAccept()
	for _, v := range []TLVValue{{Name: "R-Int1", Value: "256"}, {Name: "R-Oct1", Value: "ab"}} {
		if _, err := d.ParseTLV("", "R", v); !errors.Is(err, ErrUnsupportedAttributeType) {
			t.Errorf("ParseTLV %s: err = %v", v.Name, err)
		}
		if err := d.AddTLV(reply, "", "R", v); !errors.Is(err, ErrUnsupportedAttributeType) {
			t.Errorf("AddTLV %s: err = %v", v.Name, err)
		}
	}
	if len(reply.AVPs) != 0 {
		t.Fatalf("AVPs added: %v", reply.AVPs)
	}
	for _, name := range []string{"R-Str1", "R-Int2"} {
		if _, err := d.ParseTLV("", "R", TLVValue{Name: name, Value: "1"}); !errors.Is(err, ErrEncryptedAttribute) {
			t.Errorf("ParseTLV %s: err = %v, want still encrypted", name, err)
		}
		if err := d.AddTLV(reply, "", "R", TLVValue{Name: name, Value: "1"}); err != nil {
			t.Errorf("AddTLV %s: %v", name, err)
		}
	}

	// a value hidden by a peer is shown as is, not run through the zero-stripping password scheme
	reply.AVPs = nil
	cipher := avpPassword.Encode("ab", encTLVSecret, reply.cryptAuthenticator(encryptUserPassword))
	a := AVP{Type: encTLVType, Value: append([]byte{2, byte(tlvHeaderLen + len(cipher))}, cipher...)}
	reply.AddAVP(a)
	if v, ok := d.GetTLV(reply, "", "R-Oct1"); ok {
		t.Errorf("GetTLV R-Oct1 = %q, want not found", v)
	}
	raw := avpBinary.String(nil, AVP{Value: cipher})
	if s, ok := d.GetTLVString(reply, "", "R-Oct1"); !ok || s != raw {
		t.Errorf("GetTLVString R-Oct1 = %q, %v; want %q", s, ok, raw)
	}
	if got, want := d.DecodeAVPValue(reply, a), "{R-Oct1: "+raw+"}"; got != want {
		t.Errorf("DecodeAVPValue = %q, want %q", got, want)
	}
}

// Unsupported methods fail before touching the packet, and a failing AddTLV changes nothing.
func TestAddTLVErrorNoSideEffects(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	_, err := d.ParseTLV("", "Enc-TLV", TLVValue{Name: "Enc-Secret", Value: "x"})
	if !errors.Is(err, ErrUnsupportedAttributeType) || strings.Contains(err.Error(), "AddTLV") {
		t.Errorf("ParseTLV Enc-Secret: err = %v", err)
	}
	bare := &Packet{Code: AccessAccept, Secret: encTLVSecret}
	if err := d.AddTLV(bare, "", "Enc-TLV", TLVValue{Name: "Enc-Secret", Value: "x"}); !errors.Is(err, ErrUnsupportedAttributeType) {
		t.Errorf("AddTLV Enc-Secret on a bare reply: err = %v", err)
	}
	for _, values := range [][]TLVValue{
		{{Name: "Enc-Secret", Value: "x"}},
		{{Name: "Enc-Pass", Value: "hunter2"}, {Name: "Enc-Num", Value: "x"}},
		{{Name: "Enc-Pass", Value: "hunter2"}, {Name: "Enc-Pass", Value: strings.Repeat("p", maxPasswordLen+1)}},
	} {
		p := &Packet{Code: AccessRequest, Secret: encTLVSecret}
		if err := d.AddTLV(p, "", "Enc-TLV", values...); err == nil {
			t.Errorf("%v: no error", values)
		}
		if p.Authenticator != zeroAuthenticator || len(p.AVPs) != 0 {
			t.Errorf("%v: packet changed: authenticator %x, AVPs %v", values, p.Authenticator, p.AVPs)
		}
	}
}

// Readers treat a nil packet as one without the attribute.
func TestGetNilPacket(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	gets := map[string]func() bool{
		"GetTLV":          func() bool { _, ok := d.GetTLV(nil, "", "Enc-Num"); return ok },
		"GetTLV enc":      func() bool { _, ok := d.GetTLV(nil, "", "Enc-Pass"); return ok },
		"GetTLVString":    func() bool { _, ok := d.GetTLVString(nil, "", "Enc-Num"); return ok },
		"GetTLV vendor":   func() bool { _, ok := d.GetTLV(nil, "WiMAX", "WiMAX-hDHCP-DHCP-RK-Key-Id"); return ok },
		"GetTLV extended": func() bool { _, ok := d.GetTLV(nil, "", "Ext-Enc-Pass"); return ok },
		"GetVSA":          func() bool { _, ok := d.GetVSA(nil, "WiMAX", "WiMAX-hDHCP-Server-Parameters"); return ok },
		"GetExtended":     func() bool { _, ok := d.GetExtended(nil, "", "Ext-Enc"); return ok },
	}
	for name, get := range gets {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s(nil) panics: %v", name, r)
				}
			}()
			if get() {
				t.Errorf("%s(nil) found", name)
			}
		}()
	}
}

// The sender reads its own request, and the receiver decodes it, with the zero authenticator;
// Encode sends the computed authenticator and leaves p's.
func TestEncryptZeroAuthenticatorRequest(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })
	const tunnelTag = 1
	for _, code := range zeroAuthRequestCodes {
		p := Request(code, encTLVSecret)
		p.Authenticator[0] = 1 // ignored for hiding
		if err := d.AddTLV(p, "", "Enc-TLV",
			TLVValue{Name: "Enc-Pass", Value: "hunter2"},
			TLVValue{Name: "Enc-Key", Value: "tunnel-pass"},
		); err != nil {
			t.Fatal(err)
		}
		if err := p.AddTunnelPassword(tunnelTag, "tp"); err != nil {
			t.Fatal(err)
		}
		pass, _ := findTLV(p.AVPs[0].Value, []uint8{1})
		if want := avpPassword.Encode("hunter2", encTLVSecret, make([]byte, authenticatorLen)); !bytes.Equal(pass, want) {
			t.Errorf("%v: Enc-Pass = %x, want %x", code, pass, want)
		}
		pre := p.Authenticator
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if wire := b[packetHeaderLen-authenticatorLen : packetHeaderLen]; bytes.Equal(p.Authenticator[:], wire) || p.Authenticator != pre {
			t.Fatalf("%v: authenticator %x, encoded %x, before Encode %x", code, p.Authenticator, wire, pre)
		}
		got, err := DecodeRequest(encTLVSecret, b)
		if err != nil {
			t.Fatal(err)
		}
		for which, q := range map[string]*Packet{"sender": p, "receiver": got} {
			for name, want := range map[string]string{"Enc-Pass": "hunter2", "Enc-Key": "tunnel-pass"} {
				if v, ok := d.GetTLV(q, "", name); !ok || string(v) != want {
					t.Errorf("%v %s: %s = %q, %v; want %q", code, which, name, v, ok, want)
				}
			}
			if tag, pw, ok := q.GetTunnelPassword(); !ok || tag != tunnelTag || pw != "tp" {
				t.Errorf("%v %s: Tunnel-Password = %d %q %v", code, which, tag, pw, ok)
			}
			if s := q.String(); !strings.Contains(s, "Enc-Pass: hunter2") || !strings.Contains(s, "Tunnel-Password tp") {
				t.Errorf("%v %s: String = %q", code, which, s)
			}
		}
	}
}

// A reply not built with Reply() has no request authenticator, so it can't hide values (FreeRADIUS).
func TestEncryptReplyWithoutRequest(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	tmpl, err := GetDefaultDictionary().GetTemplate("Tunnel-Password")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range replyCodes {
		p := &Packet{Code: code, Secret: encTLVSecret}
		if err := p.AddTunnelPassword(0, "tp"); !errors.Is(err, ErrNoRequestAuthenticator) {
			t.Errorf("%v: AddTunnelPassword err = %v", code, err)
		}
		if err := d.AddTLV(p, "", "Enc-TLV", TLVValue{Name: "Enc-Key", Value: "k"}); !errors.Is(err, ErrNoRequestAuthenticator) {
			t.Errorf("%v: AddTLV err = %v", code, err)
		}
		tmpl.Add(p, "tp")
		if len(p.AVPs) != 0 {
			t.Errorf("%v: AVPs added: %v", code, p.AVPs)
		}
		if err := d.AddTLV(p, "", "Enc-TLV", TLVValue{Name: "Enc-Num", Value: "1"}); err != nil {
			t.Errorf("%v: plain AddTLV: %v", code, err)
		}

		r := Request(AccessRequest, encTLVSecret).Reply()
		r.Code = code
		if err := r.AddTunnelPassword(0, "tp"); err != nil {
			t.Errorf("%v: Reply().AddTunnelPassword: %v", code, err)
		}
		if err := d.AddTLV(r, "", "Enc-TLV", TLVValue{Name: "Enc-Key", Value: "k"}); err != nil {
			t.Errorf("%v: Reply() AddTLV: %v", code, err)
		}
	}
}

// extEncType is the Extended-Type of Ext-Enc and Long-Enc in encTLVDict.
const extEncType = 7

// Encrypted children of extended and (split) long-extended TLVs decrypt with every reply decoder.
func TestTLVEncryptExtended(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	key := strings.Repeat("k", tunnelPasswordMaxLen)
	req := Request(AccessRequest, encTLVSecret)
	reply := req.ReplyAccept()
	if err := d.AddTLV(reply, "", "Ext-Enc",
		TLVValue{Name: "Ext-Enc-Pass", Value: "hunter2"},
		TLVValue{Name: "Ext-Enc-Key", Value: key},
	); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("over-long Ext-Enc: err = %v, want ErrInvalidValue", err)
	}
	if len(reply.AVPs) != 0 {
		t.Fatalf("AVPs added on error: %v", reply.AVPs)
	}
	if err := d.AddTLV(reply, "", "Ext-Enc", TLVValue{Name: "Ext-Enc-Pass", Value: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddTLV(reply, "", "Ext-Enc", TLVValue{Name: "Ext-Enc-Key", Value: key}); err != nil {
		t.Fatal(err)
	}

	// a plain blob pushes the encrypted children into the second fragment
	blob := bytes.Repeat([]byte{0}, maxLongExtData)
	encKey, err := encryptValue(encryptTunnelPassword, reply, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	encPass, err := encryptValue(encryptUserPassword, reply, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	var v []byte
	for i, c := range [][]byte{blob[:maxAVPValueLen-tlvHeaderLen], encKey, encPass} {
		v = append(v, byte(i+1), byte(tlvHeaderLen+len(c)))
		v = append(v, c...)
	}
	e := ExtendedAttr{Type: AttrLongExtendedType1, ExtType: extEncType, Value: v}
	if n := len(e.ToAVPList()); n < 2 {
		t.Fatalf("Long-Enc in %d AVPs, want split", n)
	}
	reply.AddExtended(e)

	b, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Ext-Enc-Pass": "hunter2", "Ext-Enc-Key": key, "Long-Enc-Key": key, "Long-Enc-Pass": "hunter2"}
	decoders := map[string]func() (*Packet, error){
		"DecodeReply":       func() (*Packet, error) { return DecodeReply(encTLVSecret, b, req.Authenticator[:]) },
		"DecodeReplyLazy":   func() (*Packet, error) { return DecodeReplyLazy(encTLVSecret, b, req.Authenticator[:]) },
		"DecodeReplyPooled": func() (*Packet, error) { return DecodeReplyPooled(encTLVSecret, b, req.Authenticator[:]) },
	}
	for dn, decode := range decoders {
		got, err := decode()
		if err != nil {
			t.Fatalf("%s: %v", dn, err)
		}
		for name, w := range want {
			if v, ok := d.GetTLV(got, "", name); !ok || string(v) != w {
				t.Errorf("%s: GetTLV %s = %q, %v; want %q", dn, name, v, ok, w)
			}
			if s, ok := d.GetTLVString(got, "", name); !ok || s != w {
				t.Errorf("%s: GetTLVString %s = %q, %v; want %q", dn, name, s, ok, w)
			}
		}
		got.Release()
	}
}

// encRoundTripCodes are the packet codes the round-trip fuzz hides values in.
var encRoundTripCodes = append([]PacketCode{AccessRequest, StatusServer}, append(zeroAuthRequestCodes, replyCodes...)...)

func FuzzTLVEncryptedDecode(f *testing.F) {
	d := loadTLVDict(f, encTLVDict)
	_, a := encTLVVectorPacket(f)
	f.Add(a.Value, []byte("hunter2"), uint8(0))
	f.Add([]byte{2, 20, 0x81, 0x23, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, []byte{}, uint8(1))
	f.Add(bytes.Repeat([]byte{1, 18}, 20), bytes.Repeat([]byte{0, 'x'}, maxAVPValueLen), uint8(5))
	f.Fuzz(func(t *testing.T, value, plain []byte, code uint8) {
		fuzzTLVDecrypt(d, value)
		fuzzTLVEncryptRoundTrip(t, d, plain, encRoundTripCodes[int(code)%len(encRoundTripCodes)])
	})
}

// fuzzAuthenticator is the fixed authenticator of the packets fuzzTLVDecrypt reads, so failures reproduce.
var fuzzAuthenticator = [authenticatorLen]byte{0: 1, 15: 0xff}

// fuzzTLVDecrypt reads value as standard, vendor, extended and long-extended TLVs with encrypted children,
// in a request and in a reply.
func fuzzTLVDecrypt(d *Dictionary, value []byte) {
	if len(value) > maxAVPValueLen {
		return
	}
	req := &Packet{Code: AccessRequest, Secret: encTLVSecret, Authenticator: fuzzAuthenticator}
	reply := &Packet{Code: AccessAccept, Secret: encTLVSecret, requestAuth: fuzzAuthenticator}
	for _, p := range []*Packet{req, reply} {
		p.AddAVP(AVP{Type: encTLVType, Value: value})
		p.AddVSA(VSA{Vendor: 24757, Type: 86, Value: value, Format: VendorFormat{TypeLen: 1, LengthLen: 1, Continuation: true}})
		if len(value) < maxAVPValueLen {
			p.AddAVP(AVP{Type: AttrExtendedType1, Value: append([]byte{extEncType}, value...)})
		}
		if len(value) > 0 {
			// twice, so a long value is reassembled from several fragments
			p.AddExtended(ExtendedAttr{Type: AttrLongExtendedType1, ExtType: extEncType, Value: append(bytes.Clone(value), value...)})
		}
		p.EachAVP(func(a AVP) bool {
			_ = d.DecodeAVPValue(p, a)
			return true
		})
		for _, name := range []string{"Enc-Pass", "Enc-Key", "Enc-Int", "Enc-Nest-Key", "Enc-Secret",
			"Ext-Enc-Pass", "Ext-Enc-Key", "Long-Enc-Blob", "Long-Enc-Key", "Long-Enc-Pass"} {
			_, _ = d.GetTLV(p, "", name)
			_, _ = d.GetTLVString(p, "", name)
		}
		_, _ = d.GetTLVString(p, "WiMAX", "WiMAX-hDHCP-DHCP-RK")
	}
}

// fuzzTLVEncryptRoundTrip hides plain (cut to the limits) in a packet of code; both ends read it back.
// Access-Request and Status-Server refuse encrypt=2.
func fuzzTLVEncryptRoundTrip(t *testing.T, d *Dictionary, plain []byte, code PacketCode) {
	// encrypt=1 can't keep trailing zeros
	pass := string(bytes.TrimRight(plain[:min(len(plain), maxPasswordLen)], "\x00"))
	key := string(plain[:min(len(plain), tunnelPasswordMaxLen)])
	req := Request(AccessRequest, encTLVSecret)
	p := Request(code, encTLVSecret)
	if !code.IsRequest() {
		p = req.Reply()
		p.Code = code
	}
	all := []struct {
		attr, name, want string
		tunnel           bool
	}{
		{"Enc-TLV", "Enc-Pass", pass, false},
		{"Enc-TLV", "Enc-Key", key, true},
		{"Ext-Enc", "Ext-Enc-Pass", pass, false},
		{"Ext-Enc", "Ext-Enc-Key", key, true},
		{"Long-Enc", "Long-Enc-Key", key, true},
		{"Long-Enc", "Long-Enc-Pass", pass, false},
	}
	cases := all[:0:0]
	for _, c := range all {
		err := d.AddTLV(p, "", c.attr, TLVValue{Name: c.name, Value: c.want})
		if c.tunnel && code.hasRandomAuthenticator() {
			if !errors.Is(err, ErrTunnelPasswordInRequest) {
				t.Fatalf("%v: AddTLV %s: err = %v", code, c.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%v: AddTLV %s (%d bytes): %v", code, c.name, len(c.want), err)
		}
		cases = append(cases, c)
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got *Packet
	if code.IsRequest() {
		got, err = DecodeRequest(encTLVSecret, b)
	} else {
		got, err = DecodeReply(encTLVSecret, b, req.Authenticator[:])
	}
	if err != nil {
		t.Fatalf("%v: decode: %v", code, err)
	}
	for _, q := range []*Packet{p, got} {
		for _, c := range cases {
			if v, ok := d.GetTLV(q, "", c.name); !ok || string(v) != c.want {
				t.Fatalf("%v: %s = %q, %v; want %q", code, c.name, v, ok, c.want)
			}
		}
	}
}

// Status-Server hides encrypt=1 with its own authenticator and refuses encrypt=2; its reply hides both.
func TestTLVEncryptStatusServer(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	req := Request(StatusServer, encTLVSecret)
	if err := d.AddTLV(req, "", "Enc-TLV", TLVValue{Name: "Enc-Key", Value: "tunnel-pass"}); !errors.Is(err, ErrTunnelPasswordInRequest) {
		t.Errorf("AddTLV Enc-Key: err = %v, want ErrTunnelPasswordInRequest", err)
	}
	if err := d.AddTLV(req, "", "Enc-TLV", TLVValue{Name: "Enc-Pass", Value: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	pass, _ := findTLV(req.AVPs[0].Value, []uint8{1})
	if want := avpPassword.Encode("hunter2", encTLVSecret, req.Authenticator[:]); !bytes.Equal(pass, want) {
		t.Errorf("Enc-Pass = %x, want %x", pass, want)
	}
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	gotReq, err := DecodeRequest(encTLVSecret, b)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.GetTLV(gotReq, "", "Enc-Pass"); !ok || string(v) != "hunter2" {
		t.Errorf("request Enc-Pass = %q, %v", v, ok)
	}

	reply := gotReq.ReplyAccept()
	if err := d.AddTLV(reply, "", "Enc-TLV",
		TLVValue{Name: "Enc-Pass", Value: "hunter2"},
		TLVValue{Name: "Enc-Key", Value: "tunnel-pass"},
	); err != nil {
		t.Fatal(err)
	}
	b, err = reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeReply(encTLVSecret, b, req.Authenticator[:])
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"Enc-Pass": "hunter2", "Enc-Key": "tunnel-pass"} {
		if v, ok := d.GetTLV(got, "", name); !ok || string(v) != want {
			t.Errorf("reply %s = %q, %v; want %q", name, v, ok, want)
		}
	}
}

// A TLV alias shares the first definition, so its own encrypt= is ignored with a warning.
func TestTLVAliasEncryptWarn(t *testing.T) {
	for name, dict := range map[string]string{
		"standard": "ATTRIBUTE A 200 tlv\nATTRIBUTE A-1 200.1 integer\nATTRIBUTE B 200 tlv encrypt=2\n",
		"extended": "ATTRIBUTE Extended-Attribute-1 241 extended\nATTRIBUTE A 241.7 tlv\nATTRIBUTE A-1 241.7.1 integer\nATTRIBUTE B 241.7 tlv encrypt=2\n",
	} {
		h := useRecordLogger(t)
		d := loadTLVDict(t, dict)
		if !strings.Contains(h.all(), "not supported") || !strings.Contains(h.all(), "attribute=B") {
			t.Errorf("%s: no warning:\n%s", name, h.all())
		}
		if _, err := d.ParseTLV("", "B", TLVValue{Name: "A-1", Value: "1"}); err != nil {
			t.Errorf("%s: ParseTLV through the alias: %v", name, err)
		}
	}
}
