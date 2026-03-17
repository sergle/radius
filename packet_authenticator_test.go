package radius

import "testing"

// Ensure that non-Access request authenticators are computed using a zero
// vector in the hash input, even if the caller pre-populates Authenticator.
func TestNonAccessRequestAuthenticatorUsesZeroVector(t *testing.T) {
	const secret = "testing123"

	p := &Packet{
		Secret:     secret,
		Code:       AccountingRequest,
		Identifier: 1,
	}

	// Deliberately set a non-zero authenticator to simulate a buggy caller.
	for i := range p.Authenticator {
		p.Authenticator[i] = byte(i + 1)
	}

	// Encode and then decode using the library's own verifier. If the encoder
	// hashed with the non-zero authenticator instead of zeros, verification
	// will fail.
	b, err := p.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if _, err := DecodeRequest(secret, b); err != nil {
		t.Fatalf("DecodeRequest failed: %v", err)
	}
}

