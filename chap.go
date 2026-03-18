package radius

import (
	"crypto"
	_ "crypto/md5"
	"errors"
)

// CHAPPassword is the decoded form of the CHAP-Password attribute (RFC 2865).
//
// The on-the-wire value is 17 bytes: 1 byte CHAP ID followed by 16 bytes response.
type CHAPPassword struct {
	ID       uint8
	Response [16]byte
}

var (
	ErrInvalidCHAPChallengeLength = errors.New("invalid CHAP-Challenge length (must be 1..16 bytes)")
	ErrInvalidCHAPPasswordLength  = errors.New("invalid CHAP-Password length (must be 17 bytes)")
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
	if len(challenge) < 1 || len(challenge) > 16 {
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
	if len(avp.Value) != 17 {
		return CHAPPassword{}, false
	}
	var out CHAPPassword
	out.ID = avp.Value[0]
	copy(out.Response[:], avp.Value[1:17])
	return out, true
}

// SetCHAPPassword adds or replaces the CHAP-Password attribute using the provided
// CHAP ID and 16-byte response.
func (p *Packet) SetCHAPPassword(chapID uint8, response16 [16]byte) {
	value := make([]byte, 17)
	value[0] = chapID
	copy(value[1:], response16[:])
	p.SetAVP(AVP{Type: AttrCHAPPassword, Value: value})
}

// ComputeCHAPResponse computes the CHAP response as MD5(chapID || password || challenge).
func ComputeCHAPResponse(chapID uint8, password string, challenge []byte) ([16]byte, error) {
	if len(challenge) < 1 || len(challenge) > 16 {
		return [16]byte{}, ErrInvalidCHAPChallengeLength
	}

	h := crypto.MD5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(password))
	h.Write(challenge)

	sum := h.Sum(nil)
	if len(sum) != 16 {
		// Should never happen for MD5.
		return [16]byte{}, errors.New("unexpected CHAP response length")
	}
	var out [16]byte
	copy(out[:], sum)
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

