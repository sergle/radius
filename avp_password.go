package radius

import (
	"bytes"
	"crypto"
)

const blockSize = 16

var avpPassword AvpPassword

type AvpPassword struct{}

func (s AvpPassword) Value(p *Packet, a AVP) interface{} {
	if p == nil {
		return ""
	}

	b := a.Value
	password := make([]byte, len(b))
	last := make([]byte, blockSize)
	copy(last, p.Authenticator[:])
	hash := crypto.Hash(crypto.MD5).New()
	blocks := 0

	for len(b) > 0 {
		hash.Write(append([]byte(p.Secret), last...))
		digest := hash.Sum(nil)
		hash.Reset()

		// see crypto/cipher/xor.go for faster implementation
		for i := 0; i < blockSize; i++ {
			password[blockSize*blocks+i] = b[i] ^ digest[i]
		}
		// next block
		last = b[:blockSize]
		b = b[blockSize:]
		blocks += 1
	}

	//remove padding zeroes
	password = bytes.TrimRight(password, string([]byte{0}))
	return string(password)
}

func (s AvpPassword) String(p *Packet, a AVP) string {
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
