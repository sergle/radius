package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestAVPPassword(t *testing.T) {
	pass := "test-password"
	secret := "my-secret-key"
	auth := []byte("1234567812345678")

	pac := &Packet{Secret: secret}
	copy(pac.Authenticator[:], auth)

	encoded := avpPassword.Encode(pass, secret, auth)
	if len(encoded)%16 != 0 {
		t.Errorf("Encoded password length should be multiple of 16, got %d", len(encoded))
	}

	avp := AVP{Type: AttrUserPassword, Value: encoded}
	dec := avpPassword.Value(pac, avp).(string)
	if dec != pass {
		t.Errorf("Decode failed: got %s, want %s", dec, pass)
	}

	// Test with different secret and authenticator
	pac2 := &Packet{Secret: "another-secret"}
	copy(pac2.Authenticator[:], "another-auth6789")
	encoded2 := avpPassword.Encode(pass, pac2.Secret, pac2.Authenticator[:])
	avp2 := AVP{Type: AttrUserPassword, Value: encoded2}
	dec2 := avpPassword.Value(pac2, avp2).(string)
	if dec2 != pass {
		t.Errorf("Decode with pac2 failed: got %s, want %s", dec2, pass)
	}

	// Verify encryption actually works (different secrets should produce different ciphertexts)
	if bytes.Equal(encoded, encoded2) {
		t.Error("Ciphertexts for different secrets should not be the same")
	}
}

func TestAVPPasswordPadding(t *testing.T) {
	secret := "secret"
	auth := make([]byte, 16)
	pac := &Packet{Secret: secret}
	copy(pac.Authenticator[:], auth)

	testCases := []string{
		"123456789012",      // 12 chars
		"1234567890123456",  // 16 chars
		"12345678901234567", // 17 chars
	}

	for _, pass := range testCases {
		encoded := avpPassword.Encode(pass, secret, auth)
		if len(encoded) == 0 || len(encoded)%16 != 0 {
			t.Errorf("Invalid encoded length %d for password length %d", len(encoded), len(pass))
		}
		avp := AVP{Type: AttrUserPassword, Value: encoded}
		dec := avpPassword.Value(pac, avp).(string)
		if dec != pass {
			t.Errorf("Padding test failed for '%s': got '%s'", pass, dec)
		}
	}
}

func TestAVPPasswordGolden(t *testing.T) {
	// These are hardcoded values to ensure we remain compatible with standard RADIUS implementations (RFC 2865)
	authenticator := []byte{
		0x37, 0x4c, 0x72, 0x21, 0x3f, 0xb1, 0x66, 0xbe,
		0x67, 0x14, 0xef, 0x83, 0x78, 0x78, 0x61, 0xf0,
	}
	secret := "top-secret"
	pac := &Packet{Secret: secret}
	copy(pac.Authenticator[:], authenticator)

	// CASE 1: "super-password"
	encoded1 := []byte{
		0xB6, 0x89, 0x18, 0x42, 0x3E, 0xA9, 0x9B, 0x9F,
		0x50, 0xBD, 0x7C, 0x89, 0x80, 0xC3, 0xB2, 0x11,
	}
	avp1 := AVP{Type: AttrUserPassword, Value: encoded1}
	expected1 := "super-password"
	got1 := avpPassword.Value(pac, avp1).(string)
	if got1 != expected1 {
		t.Errorf("Golden case 1 failed: got %s, want %s", got1, expected1)
	}

	// CASE 2: Long password "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" (30 chars)
	encoded2 := []byte{
		0xA4, 0x9D, 0x09, 0x46, 0x2D, 0xE5, 0x8A, 0x9F, 0x42, 0xAF, 0x6A, 0x87, 0x93, 0xC6, 0xD3, 0x70,
		0x72, 0xCA, 0x1D, 0x5B, 0xED, 0x68, 0xCA, 0xFA, 0x78, 0x92, 0x01, 0xF7, 0x44, 0x08, 0xCA, 0x98,
	}
	avp2 := AVP{Type: AttrUserPassword, Value: encoded2}
	expected2 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got2 := avpPassword.Value(pac, avp2).(string)
	if got2 != expected2 {
		t.Errorf("Golden case 2 failed: got %s, want %s", got2, expected2)
	}
}

// A hand-built Access-Request gets its random authenticator before a value is hidden, not at Encode.
func TestPasswordManualAccessRequest(t *testing.T) {
	const secret, pw, tunnelPW = "s", "secret-pw", "tunnel-pw"
	p := &Packet{Code: AccessRequest, Secret: secret}
	// refused before the authenticator is generated (Tunnel-Password is for replies)
	if err := p.AddTunnelPassword(0, tunnelPW); !errors.Is(err, ErrTunnelPasswordInRequest) || p.Authenticator != zeroAuthenticator {
		t.Fatalf("AddTunnelPassword: err = %v, authenticator %x", err, p.Authenticator)
	}
	p.AddPassword(pw)
	if p.Authenticator == zeroAuthenticator {
		t.Fatal("AddPassword left the authenticator zero")
	}
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(secret, b)
	if err != nil {
		t.Fatal(err)
	}
	for which, q := range map[string]*Packet{"sender": p, "receiver": got} {
		if q.GetPassword() != pw {
			t.Errorf("%s: User-Password = %q", which, q.GetPassword())
		}
	}
}

// RFC 2865 section 5.2: User-Password is at most 128 bytes.
func TestAddPasswordTooLong(t *testing.T) {
	p := &Packet{Code: AccessRequest, Secret: "s"}
	if err := p.AddPassword(strings.Repeat("x", maxPasswordLen)); err != nil {
		t.Fatal(err)
	}
	auth := p.Authenticator
	if err := p.AddPassword(strings.Repeat("x", maxPasswordLen+1)); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err = %v, want ErrInvalidValue", err)
	}
	if p.GetPassword() != strings.Repeat("x", maxPasswordLen) || p.Authenticator != auth {
		t.Fatal("packet changed on error")
	}

	// the template skips it
	q := &Packet{Code: AccessRequest, Secret: "s"}
	tmpl, err := GetDefaultDictionary().CreateRequestTemplate(AccessRequest, "User-Password")
	if err != nil {
		t.Fatal(err)
	}
	tmpl.Fill(q, strings.Repeat("x", maxPasswordLen+1))
	if q.HasAVP(AttrUserPassword) || q.Authenticator != zeroAuthenticator {
		t.Fatal("template added a too long password")
	}
}
