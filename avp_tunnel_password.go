package radius

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

const (
	tunnelTagLen    = 1
	tunnelSaltLen   = 2
	tunnelHeaderLen = tunnelTagLen + tunnelSaltLen
	tunnelSaltBit   = 0x80 // RFC 2868: the salt's most significant bit must be set
	maxSalts        = 1 << (8*tunnelSaltLen - 1)
	avpHeaderLen    = 2 // type + length
	maxAVPValueLen  = 255 - avpHeaderLen
	// longest password whose padded length byte + data fits in one attribute
	tunnelPasswordMaxLen = (maxAVPValueLen-tunnelHeaderLen)/blockSize*blockSize - 1
)

var ErrTunnelPasswordTooLong = errors.New("tunnel password too long")

var avpTunnelPassword AvpTunnelPassword

// saltRand is the source of salts; tests replace it.
var saltRand io.Reader = rand.Reader

// AvpTunnelPassword handles Tunnel-Password values (RFC 2868 section 3.5).
type AvpTunnelPassword struct{}

func (s AvpTunnelPassword) Value(p *Packet, a AVP) any {
	_, password, _ := s.decrypt(p, a.Value)
	return password
}

func (s AvpTunnelPassword) String(p *Packet, a AVP) string {
	if p.masks() {
		if len(a.Value) < tunnelTagLen {
			return maskedValue
		}
		return withTag(maskedValue, a.Value[0])
	}
	if tag, password, ok := s.decrypt(p, a.Value); ok {
		return withTag(printable(password), tag)
	}
	return avpBinary.String(p, a)
}

func (s AvpTunnelPassword) FromString(v string) []byte {
	// FromString cannot encrypt without the Secret and Request Authenticator.
	// Use Packet.AddTunnelPassword or AvpTunnelPassword.Encode instead.
	return []byte(v)
}

// Encode encrypts password with a random salt; requestAuth is the Request Authenticator.
// The salt may repeat one in the packet; Packet.AddTunnelPassword keeps them unique.
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
	if _, err = io.ReadFull(saltRand, salt[:]); err != nil {
		return salt, err
	}
	salt[0] |= tunnelSaltBit
	return salt, nil
}

// encodeTunnelPassword is Encode with p's Secret, authenticator and a salt unique in p.
func (p *Packet) encodeTunnelPassword(tag uint8, password string) ([]byte, error) {
	auth, err := p.encryptAuthenticator(encryptTunnelPassword)
	if err != nil {
		return nil, err
	}
	if len(password) > tunnelPasswordMaxLen {
		return nil, ErrTunnelPasswordTooLong
	}
	salt, err := p.newSalt()
	if err != nil {
		return nil, err
	}
	return tunnelPasswordEncrypt(tag, salt, password, p.Secret, auth), nil
}

// newSalt returns a random salt not generated for p before (RFC 2868 section 3.5, RFC 2548 section 2.4.2).
func (p *Packet) newSalt() ([tunnelSaltLen]byte, error) {
	if len(p.salts) >= maxSalts {
		// far more encrypted values than a packet holds
		return [tunnelSaltLen]byte{}, fmt.Errorf("%w: no unique salt left", ErrInvalidPacketLength)
	}
	for {
		salt, err := newTunnelSalt()
		if err != nil {
			return salt, err
		}
		s := binary.BigEndian.Uint16(salt[:])
		if !slices.Contains(p.salts, s) {
			p.salts = append(p.salts, s)
			return salt, nil
		}
	}
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
		for j := range blockSize {
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
		for j := range blockSize {
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
