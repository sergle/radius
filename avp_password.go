package radius

import (
	"bytes"
	"crypto"
)

const (
	blockSize      = 16
	maxPasswordLen = 128 // RFC 2865 section 5.2
)

var avpPassword AvpPassword

type AvpPassword struct{}

func (s AvpPassword) Value(p *Packet, a AVP) interface{} {
	if p == nil {
		return ""
	}
	password, _ := passwordDecrypt(p.Secret, p.cryptAuthenticator(encryptUserPassword), a.Value)
	return string(password)
}

// passwordDecrypt reverses RFC 2865 hiding of b and removes the zero padding.
func passwordDecrypt(secret string, authenticator, b []byte) ([]byte, bool) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, false
	}
	password := make([]byte, len(b))
	last := authenticator
	hash := crypto.Hash(crypto.MD5).New()
	for i := 0; i < len(b); i += blockSize {
		hash.Write([]byte(secret))
		hash.Write(last)
		digest := hash.Sum(nil)
		hash.Reset()
		for j := 0; j < blockSize; j++ {
			password[i+j] = b[i+j] ^ digest[j]
		}
		// next block
		last = b[i : i+blockSize]
	}
	return bytes.TrimRight(password, "\x00"), true
}

func (s AvpPassword) String(p *Packet, a AVP) string {
	if p.masks() {
		return maskedValue
	}
	return s.Value(p, a).(string)
}

func (s AvpPassword) FromString(v string) []byte {
	// FromString cannot encode the password because it lacks the Secret and Authenticator.
	// Use Packet.AddPassword or AvpPassword.Encode instead.
	return []byte(v)
}

// Encode the password according to RFC 2865.
func (s AvpPassword) Encode(password, secret string, authenticator []byte) []byte {
	p := []byte(password)
	passLen := len(p)

	// Password must be at least 16 bytes and a multiple of 16.
	// It is padded with nulls (0x00).
	paddedLen := passLen
	if paddedLen < blockSize {
		paddedLen = blockSize
	} else if paddedLen%blockSize != 0 {
		paddedLen = ((passLen / blockSize) + 1) * blockSize
	}

	padded := make([]byte, paddedLen)
	copy(padded, p)

	c := make([]byte, paddedLen)
	last := make([]byte, blockSize)
	copy(last, authenticator)
	hash := crypto.Hash(crypto.MD5).New()

	for i := 0; i < paddedLen; i += blockSize {
		hash.Write([]byte(secret))
		hash.Write(last)
		digest := hash.Sum(nil)
		hash.Reset()

		for j := 0; j < blockSize; j++ {
			c[i+j] = padded[i+j] ^ digest[j]
		}
		// Next block's vector is the previous ciphertext block
		copy(last, c[i:i+blockSize])
	}
	return c
}
