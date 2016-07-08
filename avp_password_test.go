package radius

import (
	"testing"
)

func TestAvpPasswordValue(ot *testing.T) {

	authenticator := [16]byte{'\x37', '\x4c', '\x72', '\x21', '\x3f', '\xb1', '\x66',
		'\xbe', '\x67', '\x14', '\xef', '\x83', '\x78', '\x78', '\x61', '\xf0'}
	ok(len(authenticator) == 16)

	p := &Packet{Authenticator: authenticator, Secret: "top-secret"}
	ok(p != nil)

	encoded := []byte{'\xB6', '\x89', '\x18', '\x42', '\x3E', '\xA9', '\x9B',
		'\x9F', '\x50', '\xBD', '\x7C', '\x89', '\x80', '\xC3', '\xB2', '\x11'}
	avp := AVP{Type: UserPassword, Value: encoded}

	expected_pwd := "super-password"
	password := avpPassword.Value(p, avp).(string)
	ok(len(password) == 14)
	ok(password == expected_pwd)

	// long password
	encoded2 := []byte{
		'\xA4', '\x9D', '\x09', '\x46', '\x2D', '\xE5', '\x8A', '\x9F', '\x42', '\xAF', '\x6A', '\x87', '\x93', '\xC6', '\xD3', '\x70',
		'\x72', '\xCA', '\x1D', '\x5B', '\xED', '\x68', '\xCA', '\xFA', '\x78', '\x92', '\x01', '\xF7', '\x44', '\x08', '\xCA', '\x98',
	}
	avp2 := AVP{Type: UserPassword, Value: encoded2}
	expected_pwd2 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	password2 := avpPassword.Value(p, avp2).(string)
	ok(len(password2) == 30)
	ok(password2 == expected_pwd2)
}
