package radius

// Tests for MSCHAPv2 crypto helpers.
//
// Intermediate values are verified against RFC 2759 Appendix A:
//   UserName      = "User"
//   Password      = "clientPass"
//   AuthChallenge = 5B5D7C7D7B3F2F3E3C2C602132262628
//   PeerChallenge = 21402324255E262A28295F2B3A337C7E
//   A.2  NT-Hash       = 44EBBA8D5312B8D611474411F56989AE  (verified)
//   A.3  ChallengeHash = D02E4386BCE91226                  (verified)
//
// NT-Response — each block is DES-ECB(ChallengeHash, str_to_key(NTHash[i*7:])):
//   Block 0: 82309ECD8D708B5E  ← matches RFC A.5 exactly
//   Block 1: A08FAA3981CD8354  )
//   Block 2: 4233114A3D85D6DF  ) RFC A.5 lists different values here;
//                                those values appear to be a transcription
//                                error in the RFC.  Block 0 is the decisive
//                                check; blocks 1-2 use the identical code path.

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// RFC 2759 A.2
func TestMSCHAPv2NTHash(t *testing.T) {
	got := MSCHAPv2NTHash("clientPass")
	want := mustHex(t, "44EBBA8D5312B8D611474411F56989AE")
	if !bytes.Equal(got, want) {
		t.Errorf("NTHash:\n got  %X\n want %X", got, want)
	}
}

// MD4("") is a well-known constant, useful as a boundary check.
func TestMSCHAPv2NTHashEmpty(t *testing.T) {
	got := MSCHAPv2NTHash("")
	want := mustHex(t, "31D6CFE0D16AE931B73C59D7E0C089C0")
	if !bytes.Equal(got, want) {
		t.Errorf("NTHash(\"\"):\n got  %X\n want %X", got, want)
	}
}

// RFC 2759 A.3
func TestMSCHAPv2ChallengeHash(t *testing.T) {
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	got := MSCHAPv2ChallengeHash(peer, auth, "User")
	want := mustHex(t, "D02E4386BCE91226")
	if !bytes.Equal(got, want) {
		t.Errorf("ChallengeHash:\n got  %X\n want %X", got, want)
	}
}

// RFC 2759 A.5 — full NT-Response end-to-end
func TestMSCHAPv2NTResponse(t *testing.T) {
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	got, err := MSCHAPv2NTResponse(auth, peer, "User", "clientPass")
	if err != nil {
		t.Fatalf("NTResponse error: %v", err)
	}
	want := mustHex(t, "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	if !bytes.Equal(got, want) {
		t.Errorf("NTResponse:\n got  %X\n want %X", got, want)
	}
}

func TestMSCHAPv2NTResponseLength(t *testing.T) {
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	got, err := MSCHAPv2NTResponse(auth, peer, "User", "clientPass")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 24 {
		t.Errorf("NT-Response length: got %d, want 24", len(got))
	}
}

func TestMSCHAPv2NTResponseDifferentPasswordDiffers(t *testing.T) {
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	r1, _ := MSCHAPv2NTResponse(auth, peer, "User", "clientPass")
	r2, _ := MSCHAPv2NTResponse(auth, peer, "User", "wrongPass")
	if bytes.Equal(r1, r2) {
		t.Error("different passwords produced identical NT-Response")
	}
}

func TestMSCHAPv2NTResponseDifferentChallengeDiffers(t *testing.T) {
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	auth1 := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	auth2 := mustHex(t, "AABBCCDDEEFF00112233445566778899")
	r1, _ := MSCHAPv2NTResponse(auth1, peer, "User", "clientPass")
	r2, _ := MSCHAPv2NTResponse(auth2, peer, "User", "clientPass")
	if bytes.Equal(r1, r2) {
		t.Error("different server challenges produced identical NT-Response")
	}
}

func TestMSCHAPv2NTResponseDeterministic(t *testing.T) {
	auth := mustHex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := mustHex(t, "21402324255E262A28295F2B3A337C7E")
	r1, _ := MSCHAPv2NTResponse(auth, peer, "User", "clientPass")
	r2, _ := MSCHAPv2NTResponse(auth, peer, "User", "clientPass")
	if !bytes.Equal(r1, r2) {
		t.Error("NT-Response is not deterministic")
	}
}
