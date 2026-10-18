package radius

import (
	"strings"
	"testing"
)

// StringMasked hides encrypted values that String shows.
func TestStringMasked(t *testing.T) {
	const secret = "testing123"
	d := loadTLVDict(t, encTLVDict+"ATTRIBUTE\tUser-Password\t2\tstring\tencrypt=1\n"+saltTestDict+saltIntDict)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })

	req := Request(AccessRequest, secret)
	if err := req.AddPassword("pw-user"); err != nil {
		t.Fatal(err)
	}
	if err := addTLV(d, req, "", "Enc-TLV", tlvValue{Name: "Enc-Pass", Value: "pw-tlv"}); err != nil {
		t.Fatal(err)
	}
	reply := req.ReplyAccept()
	if err := reply.AddTunnelPassword(1, "pw-tunnel"); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, reply, "Test", "Test-Secret", "pw-salt"); err != nil {
		t.Fatal(err)
	}
	if err := addTLV(d, reply, "", "Enc-TLV", tlvValue{Name: "Enc-Key", Value: "pw-tlv2"}); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, reply, "Alcatel-Lucent-Service-Router", "Alc-LI-Destination", "10.9.8.7"); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"pw-user", "pw-tlv", "pw-tunnel", "pw-salt", "pw-tlv2", "10.9.8.7"}

	var shown, masked, decoded string
	for _, p := range []*Packet{req, reply} {
		shown += p.String()
		masked += p.StringMasked()
		for _, a := range p.AVPs {
			shown += a.StringWithPacket(p) + d.DecodeAVPValue(p, a)
			masked += a.StringMasked(p) + a.StringMasked(nil)
			decoded += d.DecodeAVPValueMasked(p, a) + "\n"
		}
	}
	masked += decoded
	for _, s := range secrets {
		if !strings.Contains(shown, s) {
			t.Errorf("String output misses %q:\n%s", s, shown)
		}
		if strings.Contains(masked, s) {
			t.Errorf("StringMasked output shows %q:\n%s", s, masked)
		}
	}
	if n := strings.Count(req.StringMasked()+reply.StringMasked(), maskedValue); n != len(secrets) {
		t.Errorf("StringMasked output has %d %s, want %d", n, maskedValue, len(secrets))
	}
	if n := strings.Count(decoded, maskedValue); n != len(secrets) {
		t.Errorf("DecodeAVPValueMasked output has %d %s, want %d:\n%s", n, maskedValue, len(secrets), decoded)
	}
}

const msDict = `VENDOR	Microsoft	311
BEGIN-VENDOR	Microsoft
ATTRIBUTE	MS-CHAP-Response	1	octets
ATTRIBUTE	MS-CHAP2-Response	25	octets
END-VENDOR	Microsoft
`

// StringMasked also hides credential-equivalent values: CHAP, Digest and
// MS-CHAP responses, Digest-HA1 and EAP MS-CHAPv2 data.
func TestStringMaskedCredentials(t *testing.T) {
	cred := []byte{0xc0, 0xff, 0xee, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	const credBytes = "0xc0, 0xff, 0xee" // cred as formatted bytes
	secrets := []string{credBytes, "resp-secret", "ha1-secret"}
	for _, withMS := range []bool{false, true} {
		d := NewDictionary()
		if err := d.LoadBuiltin(); err != nil {
			t.Fatal(err)
		}
		if withMS {
			if err := d.loadReader("ms", strings.NewReader(msDict)); err != nil {
				t.Fatal(err)
			}
		}
		old := GetDefaultDictionary()
		SetDefaultDictionary(d)

		p := Request(AccessRequest, "testing123")
		p.SetCHAPPassword(1, [chapResponseLen]byte(cred))
		p.AddAVP(AVP{Type: AttrDigestResponse, Value: []byte("resp-secret")})
		p.AddAVP(AVP{Type: AttrDigestHA1, Value: []byte("ha1-secret")})
		p.SetEAPMessage((&MsChapV2Packet{
			Eap:    &EapPacket{Code: EapCodeResponse, Identifier: 7, Type: EapTypeMSCHAPV2},
			OpCode: MsChapV2OpCodeResponse,
			Data:   cred,
		}).ToEap())
		p.AddAVP(VSA{Vendor: vendorMicrosoft, Type: 1, Value: cred}.ToAVP())
		p.AddAVP(VSA{Vendor: vendorMicrosoft, Type: 25, Value: cred}.ToAVP())

		shown := p.String()
		masked := []string{p.StringMasked()}
		for _, a := range p.AVPs {
			shown += d.DecodeAVPValue(p, a)
			masked = append(masked, a.StringMasked(p), d.DecodeAVPValueMasked(p, a))
		}
		for _, s := range secrets {
			if !strings.Contains(shown, s) {
				t.Errorf("ms=%v: String output misses %q:\n%s", withMS, s, shown)
			}
			for _, m := range masked {
				if strings.Contains(m, s) {
					t.Errorf("ms=%v: masked output shows %q:\n%s", withMS, s, m)
				}
			}
		}
		// CHAP-Password, Digest-Response, Digest-HA1 and the two VSAs
		if n := strings.Count(masked[0], maskedValue); n != 5 {
			t.Errorf("ms=%v: StringMasked has %d %s, want 5:\n%s", withMS, n, maskedValue, masked[0])
		}
		if !strings.Contains(masked[0], "OpCode:Response") {
			t.Errorf("ms=%v: StringMasked misses the MS-CHAPv2 opcode:\n%s", withMS, masked[0])
		}
		SetDefaultDictionary(old)
	}
}
