package radius

import (
	"crypto"
	"crypto/md5"
	"crypto/subtle"
	"errors"
)

const (
	chapIDLen       = 1
	chapResponseLen = md5.Size
	chapPasswordLen = chapIDLen + chapResponseLen
	// RFC 2865 bounds the challenge only by the attribute value size
	maxCHAPChallengeLen = maxAVPValueLen
)

// CHAPPassword is the decoded form of the CHAP-Password attribute (RFC 2865).
//
// The on-the-wire value is 17 bytes: 1 byte CHAP ID followed by 16 bytes response.
type CHAPPassword struct {
	ID       uint8
	Response [chapResponseLen]byte
}

var (
	ErrInvalidCHAPChallengeLength = errors.New("invalid CHAP-Challenge length (must be 1..253 bytes)")
	ErrInvalidCHAPPasswordLength  = errors.New("invalid CHAP-Password length (must be 17 bytes)")
	ErrCHAPPasswordMissing        = errors.New("CHAP-Password missing")
)

// GetCHAPChallenge returns CHAP-Challenge value bytes, if present.
//
// The returned slice is a copy and is safe to keep.
func (p *Packet) GetCHAPChallenge() []byte {
	avp := p.GetAVP(AttrCHAPChallenge)
	if avp == nil {
		return nil
	}
	out := make([]byte, len(avp.Value))
	copy(out, avp.Value)
	return out
}

// SetCHAPChallenge adds or replaces the CHAP-Challenge attribute.
func (p *Packet) SetCHAPChallenge(challenge []byte) error {
	if len(challenge) < 1 || len(challenge) > maxCHAPChallengeLen {
		return ErrInvalidCHAPChallengeLength
	}
	value := make([]byte, len(challenge))
	copy(value, challenge)
	p.SetAVP(AVP{Type: AttrCHAPChallenge, Value: value})
	return nil
}

// GetCHAPPassword returns the decoded CHAP-Password value if present and well-formed.
func (p *Packet) GetCHAPPassword() (CHAPPassword, bool) {
	avp := p.GetAVP(AttrCHAPPassword)
	if avp == nil {
		return CHAPPassword{}, false
	}
	if len(avp.Value) != chapPasswordLen {
		return CHAPPassword{}, false
	}
	var out CHAPPassword
	out.ID = avp.Value[0]
	copy(out.Response[:], avp.Value[chapIDLen:])
	return out, true
}

// SetCHAPPassword adds or replaces the CHAP-Password attribute using the provided
// CHAP ID and 16-byte response.
func (p *Packet) SetCHAPPassword(chapID uint8, response [chapResponseLen]byte) {
	value := make([]byte, chapPasswordLen)
	value[0] = chapID
	copy(value[chapIDLen:], response[:])
	p.SetAVP(AVP{Type: AttrCHAPPassword, Value: value})
}

// ComputeCHAPResponse computes the CHAP response as MD5(chapID || password || challenge).
func ComputeCHAPResponse(chapID uint8, password string, challenge []byte) ([chapResponseLen]byte, error) {
	if len(challenge) < 1 || len(challenge) > maxCHAPChallengeLen {
		return [chapResponseLen]byte{}, ErrInvalidCHAPChallengeLength
	}

	h := crypto.MD5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(password))
	h.Write(challenge)

	var out [chapResponseLen]byte
	h.Sum(out[:0])
	return out, nil
}

// SetCHAPPasswordFromSecret computes and sets both CHAP-Password and CHAP-Challenge.
func (p *Packet) SetCHAPPasswordFromSecret(chapID uint8, password string, challenge []byte) error {
	resp, err := ComputeCHAPResponse(chapID, password, challenge)
	if err != nil {
		return err
	}
	if err := p.SetCHAPChallenge(challenge); err != nil {
		return err
	}
	p.SetCHAPPassword(chapID, resp)
	return nil
}

// VerifyCHAP checks CHAP-Password against password (RFC 2865 section 2.2).
//
// The challenge is CHAP-Challenge if present, otherwise the Request Authenticator.
// An error is returned for a missing or malformed CHAP-Password or CHAP-Challenge.
func (p *Packet) VerifyCHAP(password string) (bool, error) {
	avp := p.GetAVP(AttrCHAPPassword)
	if avp == nil {
		return false, ErrCHAPPasswordMissing
	}
	if len(avp.Value) != chapPasswordLen {
		return false, ErrInvalidCHAPPasswordLength
	}
	challenge := p.Authenticator[:]
	if c := p.GetAVP(AttrCHAPChallenge); c != nil {
		challenge = c.Value
	}
	want, err := ComputeCHAPResponse(avp.Value[0], password, challenge)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(want[:], avp.Value[chapIDLen:]) == 1, nil
}
