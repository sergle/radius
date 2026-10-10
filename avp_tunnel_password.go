package radius

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
)

const (
	tunnelTagLen    = 1
	tunnelSaltLen   = 2
	tunnelHeaderLen = tunnelTagLen + tunnelSaltLen
	tunnelSaltBit   = 0x80 // RFC 2868: the salt's most significant bit must be set
	maxAVPValueLen  = 255 - 2
	// longest password whose padded length byte + data fits in one attribute
	tunnelPasswordMaxLen = (maxAVPValueLen-tunnelHeaderLen)/blockSize*blockSize - 1
)

var ErrTunnelPasswordTooLong = errors.New("tunnel password too long")

var avpTunnelPassword AvpTunnelPassword

// AvpTunnelPassword handles Tunnel-Password values (RFC 2868 section 3.5).
type AvpTunnelPassword struct{}

func (s AvpTunnelPassword) Value(p *Packet, a AVP) interface{} {
	_, password, _ := s.decrypt(p, a.Value)
	return password
}

func (s AvpTunnelPassword) String(p *Packet, a AVP) string {
	if _, password, ok := s.decrypt(p, a.Value); ok {
		return password
	}
	return avpBinary.String(p, a)
}

func (s AvpTunnelPassword) FromString(v string) []byte {
	// FromString cannot encrypt without the Secret and Request Authenticator.
	// Use Packet.AddTunnelPassword or AvpTunnelPassword.Encode instead.
	return []byte(v)
}

// Encode encrypts password with a random salt; requestAuth is the Request Authenticator.
func (s AvpTunnelPassword) Encode(tag uint8, password, secret string, requestAuth []byte) ([]byte, error) {
	if len(password) > tunnelPasswordMaxLen {
		return nil, ErrTunnelPasswordTooLong
	}
	salt, err := newTunnelSalt()
	if err != nil {
		return nil, err
	}
	return tunnelPasswordEncrypt(tag, salt, password, secret, requestAuth), nil
}

// newTunnelSalt returns a random salt with the high bit set.
func newTunnelSalt() (salt [tunnelSaltLen]byte, err error) {
	if _, err = rand.Read(salt[:]); err != nil {
		return salt, err
	}
	salt[0] |= tunnelSaltBit
	return salt, nil
}

func tunnelPasswordEncrypt(tag uint8, salt [tunnelSaltLen]byte, password, secret string, requestAuth []byte) []byte {
	// plaintext: length byte + password, zero-padded to the block size
	plain := make([]byte, (1+len(password)+blockSize-1)/blockSize*blockSize)
	plain[0] = byte(len(password))
	copy(plain[1:], password)

	out := make([]byte, tunnelHeaderLen+len(plain))
	out[0] = tag
	copy(out[tunnelTagLen:], salt[:])
	c := out[tunnelHeaderLen:]

	h := md5.New()
	h.Write([]byte(secret))
	h.Write(requestAuth)
	h.Write(salt[:])
	for i := 0; i < len(plain); i += blockSize {
		b := h.Sum(nil)
		for j := 0; j < blockSize; j++ {
			c[i+j] = plain[i+j] ^ b[j]
		}
		h.Reset()
		h.Write([]byte(secret))
		h.Write(c[i : i+blockSize])
	}
	return out
}

func (s AvpTunnelPassword) decrypt(p *Packet, v []byte) (tag uint8, password string, ok bool) {
	if p == nil || len(v) < tunnelTagLen {
		return 0, "", false
	}
	plain, ok := tunnelPasswordDecrypt(p.Secret, p.cryptAuthenticator(encryptTunnelPassword), v[tunnelTagLen:])
	if !ok {
		return 0, "", false
	}
	return v[0], string(plain), true
}

// tunnelPasswordDecrypt decrypts v, a salt and the hidden length byte + password.
func tunnelPasswordDecrypt(secret string, requestAuth, v []byte) ([]byte, bool) {
	if len(v) < tunnelSaltLen+blockSize || (len(v)-tunnelSaltLen)%blockSize != 0 {
		return nil, false
	}
	c := v[tunnelSaltLen:]
	plain := make([]byte, len(c))

	h := md5.New()
	h.Write([]byte(secret))
	h.Write(requestAuth)
	h.Write(v[:tunnelSaltLen])
	for i := 0; i < len(c); i += blockSize {
		b := h.Sum(nil)
		for j := 0; j < blockSize; j++ {
			plain[i+j] = c[i+j] ^ b[j]
		}
		h.Reset()
		h.Write([]byte(secret))
		h.Write(c[i : i+blockSize])
	}
	n := int(plain[0])
	if n > len(plain)-1 {
		return nil, false
	}
	return plain[1 : 1+n], true
}
