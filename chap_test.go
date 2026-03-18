package radius

import (
	"bytes"
	"testing"
)

func TestComputeCHAPResponse(t *testing.T) {
	chapID := uint8(7)
	password := "s3cr3t"
	challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	got, err := ComputeCHAPResponse(chapID, password, challenge)
	if err != nil {
		t.Fatalf("ComputeCHAPResponse returned error: %v", err)
	}

	// Expected golden value: MD5(0x07 || "s3cr3t" || 01 02 03 04 05).
	want := [16]byte{
		0x66, 0x80, 0xa6, 0xbc,
		0x10, 0x1d, 0xcb, 0x4e,
		0x95, 0xb3, 0x58, 0x49,
		0x72, 0xa5, 0x75, 0x0f,
	}

	if got != want {
		t.Fatalf("CHAP response mismatch: got %x want %x", got, want)
	}
}

func TestComputeCHAPResponseRejectsInvalidChallengeLengths(t *testing.T) {
	_, err := ComputeCHAPResponse(1, "pw", nil)
	if err == nil {
		t.Fatalf("expected error for empty challenge")
	}

	long := make([]byte, 17)
	_, err = ComputeCHAPResponse(1, "pw", long)
	if err == nil {
		t.Fatalf("expected error for too-long challenge")
	}
}

func TestPacketCHAPSetAndGet(t *testing.T) {
	p := &Packet{}
	challenge := []byte("1234567890abcdef") // 16 bytes
	if err := p.SetCHAPPasswordFromSecret(9, "pw", challenge); err != nil {
		t.Fatalf("SetCHAPPasswordFromSecret returned error: %v", err)
	}

	// Challenge round-trip
	gotChal := p.GetCHAPChallenge()
	if !bytes.Equal(gotChal, challenge) {
		t.Fatalf("challenge mismatch: got %x want %x", gotChal, challenge)
	}

	// CHAP-Password structure
	cp, ok := p.GetCHAPPassword()
	if !ok {
		t.Fatalf("expected CHAP-Password to be present")
	}
	if cp.ID != 9 {
		t.Fatalf("unexpected CHAP ID: got %d want %d", cp.ID, 9)
	}

	resp, err := ComputeCHAPResponse(9, "pw", challenge)
	if err != nil {
		t.Fatalf("ComputeCHAPResponse returned error: %v", err)
	}
	if cp.Response != resp {
		t.Fatalf("CHAP response mismatch: got %x want %x", cp.Response, resp)
	}
}

func TestGetCHAPPasswordRejectsInvalidLength(t *testing.T) {
	p := &Packet{}
	p.SetAVP(AVP{Type: AttrCHAPPassword, Value: []byte{1, 2, 3}})
	_, ok := p.GetCHAPPassword()
	if ok {
		t.Fatalf("expected invalid CHAP-Password length to be rejected")
	}
}

func TestSetCHAPChallengeRejectsInvalidLength(t *testing.T) {
	p := &Packet{}

	if err := p.SetCHAPChallenge(nil); err == nil {
		t.Fatalf("expected error for empty challenge")
	}
	if err := p.SetCHAPChallenge(make([]byte, 17)); err == nil {
		t.Fatalf("expected error for too-long challenge")
	}
}

