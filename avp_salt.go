package radius

import "fmt"

var (
	avpSaltString = AvpSaltEncrypted{plain: avpString}
	avpSaltOctets = AvpSaltEncrypted{plain: avpBinary}
)

// AvpSaltEncrypted handles encrypt=2 values without a tag, e.g. MS-MPPE-Send-Key (RFC 2548 section 2.4.2):
// a salt, then the hidden length byte + value; plain handles the decrypted value, of any type.
type AvpSaltEncrypted struct {
	plain avpDataType
}

func (s AvpSaltEncrypted) decrypt(p *Packet, v []byte) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	return tunnelPasswordDecrypt(p.Secret, p.cryptAuthenticator(encryptTunnelPassword), v)
}

func (s AvpSaltEncrypted) Value(p *Packet, a AVP) interface{} {
	plain, _ := s.decrypt(p, a.Value)
	return s.plain.Value(p, AVP{Value: plain})
}

func (s AvpSaltEncrypted) String(p *Packet, a AVP) string {
	if plain, ok := s.decrypt(p, a.Value); ok && validValue(s.plain, plain) {
		return s.plain.String(p, AVP{Value: plain})
	}
	return avpBinary.String(p, a)
}

func (s AvpSaltEncrypted) FromString(v string) []byte {
	// can't encrypt without a packet, use ParseVSA and Packet.AddVSA
	return []byte(v)
}

// isEncrypted reports whether handler's values are hidden with the packet.
func isEncrypted(handler avpDataType) bool {
	switch handler.(type) {
	case AvpPassword, AvpTunnelPassword, AvpSaltEncrypted:
		return true
	}
	return false
}

// hiddenValue returns the plaintext an encrypted handler hides for value: non-strings are encoded first.
func hiddenValue(handler avpDataType, names map[string]uint32, value string) (string, error) {
	s, ok := handler.(AvpSaltEncrypted)
	if !ok || s.plain == avpString || s.plain == avpBinary {
		return value, checkHiddenLen(handler, value)
	}
	b, err := encodeValue(s.plain, names, 0, value)
	return string(b), err
}

// encryptHandlerValue hides value of an encrypted handler with p; tag is for tagged Tunnel-Passwords.
func encryptHandlerValue(p *Packet, handler avpDataType, tag uint8, value string) ([]byte, error) {
	switch handler {
	case avpPassword:
		return encryptValue(encryptUserPassword, p, []byte(value))
	case avpTunnelPassword:
		return p.encodeTunnelPassword(tag, value)
	}
	if _, ok := handler.(AvpSaltEncrypted); ok {
		return encryptValue(encryptTunnelPassword, p, []byte(value))
	}
	return nil, ErrUnsupportedAttributeType
}

// decryptHandlerValue reverses encryptHandlerValue without the tag; other handlers' values are returned as is.
// ok is false for malformed ciphertext.
func decryptHandlerValue(p *Packet, handler avpDataType, v []byte) ([]byte, bool) {
	switch handler {
	case avpPassword:
		return passwordDecrypt(p.Secret, p.cryptAuthenticator(encryptUserPassword), v)
	case avpTunnelPassword:
		if len(v) < tunnelTagLen {
			return nil, false
		}
		return tunnelPasswordDecrypt(p.Secret, p.cryptAuthenticator(encryptTunnelPassword), v[tunnelTagLen:])
	}
	if s, ok := handler.(AvpSaltEncrypted); ok {
		return s.decrypt(p, v)
	}
	return v, true
}

// checkHiddenLen reports a value too long for handler to hide in one attribute.
func checkHiddenLen(handler avpDataType, v string) error {
	n := tunnelPasswordMaxLen
	if handler == avpPassword {
		n = maxPasswordLen
	}
	if len(v) > n {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, n)
	}
	return nil
}
