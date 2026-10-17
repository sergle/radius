package radius

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const saltTestDict = `
VENDOR Microsoft 311
BEGIN-VENDOR Microsoft
ATTRIBUTE MS-MPPE-Send-Key 16 octets encrypt=2
ATTRIBUTE MS-MPPE-Recv-Key 17 octets encrypt=2
END-VENDOR Microsoft
VENDOR Test 9999
BEGIN-VENDOR Test
ATTRIBUTE Test-Secret 1 string encrypt=2
ATTRIBUTE Test-Tunnel 2 string has_tag,encrypt=2
ATTRIBUTE Test-Password 3 string encrypt=1
ATTRIBUTE Test-Name 4 string
END-VENDOR Test
`

func loadSaltDict(t *testing.T) *Dictionary {
	t.Helper()
	d := NewDictionary()
	if err := d.loadReader("salt_test", strings.NewReader(saltTestDict)); err != nil {
		t.Fatal(err)
	}
	return d
}

// saltEncrypt hides v as RFC 2548 section 2.4.2: a salt, then the length byte + v, no tag.
func saltEncrypt(v []byte, secret string, requestAuth []byte) []byte {
	return tunnelPasswordEncrypt(0, [tunnelSaltLen]byte{0x80, 0x01}, string(v), secret, requestAuth)[tunnelTagLen:]
}

// An untagged encrypt=2 VSA (MS-MPPE-Send-Key) decrypts without a tag byte.
func TestSaltEncryptedVSADecode(t *testing.T) {
	const secret = "testing123"
	d := loadSaltDict(t)
	key := bytes.Repeat([]byte{0xab}, 32)

	req := Request(AccessRequest, secret)
	reply := req.ReplyAccept()
	reply.AddVSA(VSA{Vendor: 311, Type: 16, Value: saltEncrypt(key, secret, req.Authenticator[:])})
	reply.AddVSA(VSA{Vendor: 9999, Type: 1, Value: saltEncrypt([]byte("s3cret"), secret, req.Authenticator[:])})
	b, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReply(secret, b, req.Authenticator[:])
	if err != nil {
		t.Fatal(err)
	}

	if got, ok := d.GetVSA(decoded, "Microsoft", "MS-MPPE-Send-Key"); !ok || !bytes.Equal(got, key) {
		t.Errorf("GetVSA MS-MPPE-Send-Key = %x, %v; want %x", got, ok, key)
	}
	if got, ok := d.GetVSA(decoded, "Test", "Test-Secret"); !ok || string(got) != "s3cret" {
		t.Errorf("GetVSA Test-Secret = %q, %v; want s3cret", got, ok)
	}
	if s := d.DecodeAVPValue(decoded, decoded.AVPs[1]); !strings.Contains(s, fmt.Sprintf("%#v", key)) {
		t.Errorf("DecodeAVPValue MS-MPPE-Send-Key = %s", s)
	}
	if s := d.DecodeAVPValue(decoded, decoded.AVPs[2]); !strings.Contains(s, "Value: s3cret}") {
		t.Errorf("DecodeAVPValue Test-Secret = %s", s)
	}
}

// addVSA parses a VSA and adds it to p, which encrypts it if needed.
func addVSA(d *Dictionary, p *Packet, vendor, attr, value string) error {
	vsa, err := d.ParseVSA(vendor, attr, value)
	if err != nil {
		return err
	}
	return p.AddVSA(vsa)
}

// Packet.AddVSA encrypts VSAs parsed from the dictionary.
func TestAddParsedVSA(t *testing.T) {
	const secret = "testing123"
	d := loadSaltDict(t)
	key := string(bytes.Repeat([]byte{0xcd}, 32))

	req := Request(AccessRequest, secret)
	if err := addVSA(d, req, "Test", "Test-Password", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, req, "Test", "Test-Name", "alice"); err != nil {
		t.Fatal(err)
	}
	b, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedReq, err := DecodeRequest(secret, b)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := d.GetVSA(decodedReq, "Test", "Test-Password"); !ok || string(got) != "hunter2" {
		t.Errorf("Test-Password = %q, %v", got, ok)
	}
	if got, ok := d.GetVSA(decodedReq, "Test", "Test-Name"); !ok || string(got) != "alice" {
		t.Errorf("Test-Name = %q, %v", got, ok)
	}

	reply := decodedReq.ReplyAccept()
	if err := addVSA(d, reply, "Microsoft", "MS-MPPE-Send-Key", key); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, reply, "Test", "Test-Tunnel:3", "tunnelpw"); err != nil {
		t.Fatal(err)
	}
	// no tag byte: salt + one block for the length byte and 32 bytes, rounded up
	if v := ToVSA(reply.AVPs[0]).Value; len(v) != tunnelSaltLen+3*blockSize {
		t.Errorf("MS-MPPE-Send-Key value is %d bytes, want %d", len(v), tunnelSaltLen+3*blockSize)
	}
	if v := ToVSA(reply.AVPs[1]).Value; v[0] != 3 {
		t.Errorf("Test-Tunnel tag = %d, want 3", v[0])
	}
	rb, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReply(secret, rb, req.Authenticator[:])
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := d.GetVSA(decoded, "Microsoft", "MS-MPPE-Send-Key"); !ok || string(got) != key {
		t.Errorf("MS-MPPE-Send-Key = %x, %v", got, ok)
	}
	if got, ok := d.GetVSA(decoded, "Test", "Test-Tunnel"); !ok || string(got) != "tunnelpw" {
		t.Errorf("Test-Tunnel = %q, %v", got, ok)
	}
}

// Packet.AddVSA refuses what can't be encrypted and leaves the packet unchanged.
func TestAddParsedVSAErrors(t *testing.T) {
	const secret = "testing123"
	d := loadSaltDict(t)

	tests := []struct {
		name    string
		p       *Packet
		wantErr error
	}{
		{"encrypt=2 in Access-Request", &Packet{Code: AccessRequest, Secret: secret}, ErrTunnelPasswordInRequest},
		{"reply without request", &Packet{Code: AccessAccept, Secret: secret}, ErrNoRequestAuthenticator},
	}
	vsa, err := d.ParseVSA("Microsoft", "MS-MPPE-Send-Key", "k")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := tt.p.Copy()
			if err := tt.p.AddVSA(vsa); !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
			if tt.p.Authenticator != before.Authenticator || len(tt.p.AVPs) != len(before.AVPs) {
				t.Fatal("packet changed")
			}
		})
	}

	long := strings.Repeat("k", tunnelPasswordMaxLen+1)
	if _, err := d.ParseVSA("Microsoft", "MS-MPPE-Send-Key", long); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseVSA too long: got %v, want %v", err, ErrInvalidValue)
	}
	if _, err := d.ParseVSA("Test", "Test-Password", strings.Repeat("k", maxPasswordLen+1)); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseVSA encrypt=1 too long: got %v, want %v", err, ErrInvalidValue)
	}
	p := Request(AccessRequest, secret).ReplyAccept()
	if err := p.AddVSA(VSA{Vendor: 311, Type: 300, Value: []byte("k")}); !errors.Is(err, ErrInvalidVendorFormat) {
		t.Errorf("AddVSA invalid type: got %v, want %v", err, ErrInvalidVendorFormat)
	}
}

// A parsed encrypted VSA holds the plaintext: it isn't encoded without a packet.
func TestParsedVSANotEncodedInPlaintext(t *testing.T) {
	d := loadSaltDict(t)
	vsa, err := d.ParseVSA("Microsoft", "MS-MPPE-Send-Key", "k")
	if err != nil {
		t.Fatal(err)
	}
	if avp := vsa.ToAVP(); avp.Type != 0 || avp.Value != nil {
		t.Errorf("ToAVP = %v, want zero AVP", avp)
	}
	if avps := vsa.ToAVPList(); avps != nil {
		t.Errorf("ToAVPList = %v, want nil", avps)
	}

	// the parsed VSA isn't changed by adding it: each packet encrypts its own copy
	req := Request(AccessRequest, "testing123")
	r1, r2 := req.ReplyAccept(), req.ReplyAccept()
	if err := r1.AddVSA(vsa); err != nil {
		t.Fatal(err)
	}
	if err := r2.AddVSA(vsa); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Packet{r1, r2} {
		if got, ok := d.GetVSA(r, "Microsoft", "MS-MPPE-Send-Key"); !ok || string(got) != "k" {
			t.Errorf("MS-MPPE-Send-Key = %q, %v", got, ok)
		}
	}
	if bytes.Equal(r1.AVPs[0].Value, r2.AVPs[0].Value) {
		t.Error("two packets got the same salt")
	}
}

// A VSA template builds an untagged encrypt=2 attribute.
func TestVSATemplateSaltEncrypted(t *testing.T) {
	const secret = "testing123"
	d := loadSaltDict(t)
	tpl := &RequestTemplate{code: AccessAccept}
	if err := tpl.AddVSAAttribute(d, "Microsoft", "MS-MPPE-Recv-Key"); err != nil {
		t.Fatal(err)
	}
	req := Request(AccessRequest, secret)
	reply := req.ReplyAccept()
	tpl.Fill(reply, "recv-key")
	if got, ok := d.GetVSA(reply, "Microsoft", "MS-MPPE-Recv-Key"); !ok || string(got) != "recv-key" {
		t.Fatalf("MS-MPPE-Recv-Key = %q, %v", got, ok)
	}
}

const saltIntDict = `
VENDOR Alcatel-Lucent-Service-Router 6527
BEGIN-VENDOR Alcatel-Lucent-Service-Router
ATTRIBUTE Alc-LI-Action 138 integer encrypt=2
VALUE Alc-LI-Action No-Action 1
VALUE Alc-LI-Action Enable 2
ATTRIBUTE Alc-LI-Destination 140 ipaddr encrypt=2
ATTRIBUTE Alc-Test-Signed 141 signed encrypt=2
VALUE Alc-Test-Signed Minus-One -1
ATTRIBUTE Alc-Test-Pw-Int 142 integer encrypt=1
END-VENDOR Alcatel-Lucent-Service-Router
`

// encrypt=2 on non-string types decrypts, then decodes as the type.
func TestSaltEncryptedNonString(t *testing.T) {
	const secret = "testing123"
	const vendor = "Alcatel-Lucent-Service-Router"
	d := NewDictionary()
	if err := d.loadReader("salt_int_test", strings.NewReader(saltIntDict)); err != nil {
		t.Fatal(err)
	}

	req := Request(AccessRequest, secret)
	reply := req.ReplyAccept()
	for _, v := range [][2]string{{"Alc-LI-Action", "Enable"}, {"Alc-LI-Destination", "10.1.2.3"}, {"Alc-Test-Signed", "Minus-One"}} {
		if err := addVSA(d, reply, vendor, v[0], v[1]); err != nil {
			t.Fatalf("%s: %v", v[0], err)
		}
	}
	// hand-built: decrypts to the integer 1
	reply.AddVSA(VSA{Vendor: 6527, Type: 138, Value: saltEncrypt([]byte{0, 0, 0, 1}, secret, req.Authenticator[:])})
	// encrypt=1 on an integer: not decrypted, shown as octets
	pw := []byte{0x80, 0x01, 0xde, 0xad}
	reply.AddVSA(VSA{Vendor: 6527, Type: 142, Value: pw})
	b, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReply(secret, b, req.Authenticator[:])
	if err != nil {
		t.Fatal(err)
	}
	if v := ToVSA(decoded.AVPs[1]).Value; len(v) != tunnelSaltLen+blockSize {
		t.Errorf("Alc-LI-Action value is %d bytes, want %d", len(v), tunnelSaltLen+blockSize)
	}
	if got, ok := d.GetVSA(decoded, vendor, "Alc-LI-Action"); !ok || !bytes.Equal(got, []byte{0, 0, 0, 2}) {
		t.Errorf("GetVSA Alc-LI-Action = %x, %v", got, ok)
	}
	want := []string{"Value: Enable}", "Value: 10.1.2.3}", "Value: Minus-One}", "Value: No-Action}", fmt.Sprintf("Value: %#v}", pw)}
	for i, w := range want {
		if s := d.DecodeAVPValue(decoded, decoded.AVPs[i+1]); !strings.Contains(s, w) {
			t.Errorf("DecodeAVPValue = %s, want %s", s, w)
		}
	}
	// without the packet the ciphertext is octets, not an integer
	a := decoded.AVPs[1]
	if s := d.DecodeAVPValue(nil, a); !strings.Contains(s, fmt.Sprintf("%#v}", ToVSA(a).Value)) {
		t.Errorf("DecodeAVPValue without packet = %s", s)
	}

	// a VSA template encodes the integer, then encrypts it
	tpl := &RequestTemplate{code: AccessAccept}
	if err := tpl.AddVSAAttribute(d, vendor, "Alc-LI-Action"); err != nil {
		t.Fatal(err)
	}
	r := req.ReplyAccept()
	tpl.Fill(r, "No-Action")
	if got, ok := d.GetVSA(r, vendor, "Alc-LI-Action"); !ok || !bytes.Equal(got, []byte{0, 0, 0, 1}) {
		t.Errorf("template Alc-LI-Action = %x, %v", got, ok)
	}
	if _, err := d.ParseVSA(vendor, "Alc-LI-Action", "bogus"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("ParseVSA bogus = %v, want ErrInvalidValue", err)
	}
}
