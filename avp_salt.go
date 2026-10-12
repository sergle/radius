package radius

import "fmt"

var (
	avpSaltString = AvpSaltEncrypted{plain: avpString}
	avpSaltOctets = AvpSaltEncrypted{plain: avpBinary}
)

// AvpSaltEncrypted handles encrypt=2 values without a tag, e.g. MS-MPPE-Send-Key (RFC 2548 section 2.4.2):
// a salt, then the hidden length byte + value; plain handles the decrypted value.
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
	if plain, ok := s.decrypt(p, a.Value); ok {
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
	switch handler {
	case avpPassword, avpTunnelPassword, avpSaltString, avpSaltOctets:
		return true
	}
	return false
}

// encryptHandlerValue hides value of an encrypted handler with p; tag is for tagged Tunnel-Passwords.
func encryptHandlerValue(p *Packet, handler avpDataType, tag uint8, value string) ([]byte, error) {
	switch handler {
	case avpPassword:
		return encryptValue(encryptUserPassword, p, []byte(value))
	case avpTunnelPassword:
		auth, err := p.encryptAuthenticator(encryptTunnelPassword)
		if err != nil {
			return nil, err
		}
		return avpTunnelPassword.Encode(tag, value, p.Secret, auth)
	case avpSaltString, avpSaltOctets:
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
	case avpSaltString, avpSaltOctets:
		return tunnelPasswordDecrypt(p.Secret, p.cryptAuthenticator(encryptTunnelPassword), v)
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
