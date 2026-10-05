package radius

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
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

	long := make([]byte, maxCHAPChallengeLen+1)
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
	if err := p.SetCHAPChallenge(make([]byte, maxCHAPChallengeLen+1)); err == nil {
		t.Fatalf("expected error for too-long challenge")
	}
}

// RFC 2865 limits the challenge only by the attribute value size.
func TestCHAPLongChallengeAccepted(t *testing.T) {
	for _, n := range []int{17, maxCHAPChallengeLen} {
		challenge := bytes.Repeat([]byte{0xab}, n)
		p := &Packet{}
		if err := p.SetCHAPPasswordFromSecret(3, "pw", challenge); err != nil {
			t.Fatalf("len %d: SetCHAPPasswordFromSecret: %v", n, err)
		}
		if !bytes.Equal(p.GetCHAPChallenge(), challenge) {
			t.Fatalf("len %d: challenge mismatch", n)
		}
		ok, err := p.VerifyCHAP("pw")
		if err != nil || !ok {
			t.Fatalf("len %d: VerifyCHAP = %v, %v", n, ok, err)
		}
	}
}

func TestVerifyCHAPExplicitChallenge(t *testing.T) {
	p := &Packet{Code: AccessRequest}
	// golden response from TestComputeCHAPResponse
	p.SetAVP(AVP{Type: AttrCHAPChallenge, Value: []byte{0x01, 0x02, 0x03, 0x04, 0x05}})
	p.SetCHAPPassword(7, [16]byte{
		0x66, 0x80, 0xa6, 0xbc,
		0x10, 0x1d, 0xcb, 0x4e,
		0x95, 0xb3, 0x58, 0x49,
		0x72, 0xa5, 0x75, 0x0f,
	})
	// authenticator must be ignored when CHAP-Challenge is present
	p.Authenticator = [authenticatorLen]byte{0xff}

	if ok, err := p.VerifyCHAP("s3cr3t"); err != nil || !ok {
		t.Fatalf("VerifyCHAP(correct) = %v, %v", ok, err)
	}
	if ok, err := p.VerifyCHAP("wrong"); err != nil || ok {
		t.Fatalf("VerifyCHAP(wrong) = %v, %v", ok, err)
	}
}

// chapAuthRequest builds an Access-Request whose CHAP challenge is the Request Authenticator.
func chapAuthRequest(t *testing.T, chapID uint8, password string) *Packet {
	t.Helper()
	p := &Packet{Code: AccessRequest, Identifier: 1, Secret: "secret"}
	for i := range p.Authenticator {
		p.Authenticator[i] = byte(i + 1)
	}
	resp, err := ComputeCHAPResponse(chapID, password, p.Authenticator[:])
	if err != nil {
		t.Fatalf("ComputeCHAPResponse: %v", err)
	}
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte("user")})
	p.SetCHAPPassword(chapID, resp)
	return p
}

func TestVerifyCHAPAuthenticatorFallback(t *testing.T) {
	p := chapAuthRequest(t, 5, "pw")
	if ok, err := p.VerifyCHAP("pw"); err != nil || !ok {
		t.Fatalf("VerifyCHAP(correct) = %v, %v", ok, err)
	}
	if ok, err := p.VerifyCHAP("px"); err != nil || ok {
		t.Fatalf("VerifyCHAP(wrong) = %v, %v", ok, err)
	}
}

func TestVerifyCHAPMalformed(t *testing.T) {
	p := &Packet{}
	if _, err := p.VerifyCHAP("pw"); !errors.Is(err, ErrCHAPPasswordMissing) {
		t.Fatalf("missing: got %v", err)
	}

	for _, n := range []int{0, 1, chapPasswordLen - 1, chapPasswordLen + 1} {
		p := &Packet{}
		p.SetAVP(AVP{Type: AttrCHAPPassword, Value: make([]byte, n)})
		if _, err := p.VerifyCHAP("pw"); !errors.Is(err, ErrInvalidCHAPPasswordLength) {
			t.Fatalf("len %d: got %v", n, err)
		}
	}

	p = &Packet{}
	p.SetCHAPPassword(1, [16]byte{})
	p.SetAVP(AVP{Type: AttrCHAPChallenge, Value: []byte{}})
	if _, err := p.VerifyCHAP("pw"); !errors.Is(err, ErrInvalidCHAPChallengeLength) {
		t.Fatalf("empty challenge: got %v", err)
	}
}

func TestVerifyCHAPDecoded(t *testing.T) {
	long := bytes.Repeat([]byte{0x5a}, maxCHAPChallengeLen)
	explicit := &Packet{Code: AccessRequest, Identifier: 2, Secret: "secret"}
	if err := explicit.SetCHAPPasswordFromSecret(9, "pw", long); err != nil {
		t.Fatalf("SetCHAPPasswordFromSecret: %v", err)
	}
	decoders := map[string]func(string, []byte) (*Packet, error){
		"normal": DecodeRequest,
		"pooled": DecodeRequestPooled,
		"lazy":   DecodeRequestLazy,
	}
	packets := map[string]*Packet{
		"explicit":      explicit,
		"authenticator": chapAuthRequest(t, 4, "pw"),
	}
	for pname, req := range packets {
		buf, err := req.Encode()
		if err != nil {
			t.Fatalf("%s: encode: %v", pname, err)
		}
		for dname, decode := range decoders {
			p, err := decode("secret", buf)
			if err != nil {
				t.Fatalf("%s/%s: decode: %v", pname, dname, err)
			}
			if ok, err := p.VerifyCHAP("pw"); err != nil || !ok {
				t.Fatalf("%s/%s: VerifyCHAP(correct) = %v, %v", pname, dname, ok, err)
			}
			if ok, err := p.VerifyCHAP("bad"); err != nil || ok {
				t.Fatalf("%s/%s: VerifyCHAP(wrong) = %v, %v", pname, dname, ok, err)
			}
			if dname == "pooled" {
				p.Release()
			}
		}
	}
}

func TestCHAPClientServerRoundTrip(t *testing.T) {
	const secret = "testing123"
	handler := HandlerFunc(func(ctx context.Context, req *Packet) *Packet {
		if ok, err := req.VerifyCHAP("pw"); err == nil && ok {
			return req.ReplyAccept()
		}
		return req.ReplyReject()
	})
	srv := NewServer("127.0.0.1:0", secret, handler)
	addr, _ := startTestServer(t, srv)
	client := NewRadClient(addr, secret)
	client.SetTimeout(2 * time.Second)

	tests := []struct {
		name     string
		password string
		explicit bool
		want     PacketCode
	}{
		{"long challenge", "pw", true, AccessAccept},
		{"authenticator", "pw", false, AccessAccept},
		{"wrong password", "bad", true, AccessReject},
		{"wrong password authenticator", "bad", false, AccessReject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := client.NewAccessRequest()
			req.AddAVP(AVP{Type: AttrUserName, Value: []byte("user")})
			if tt.explicit {
				challenge := bytes.Repeat([]byte{0x11}, 32)
				if err := req.SetCHAPPasswordFromSecret(1, tt.password, challenge); err != nil {
					t.Fatalf("SetCHAPPasswordFromSecret: %v", err)
				}
			} else {
				for i := range req.Authenticator {
					req.Authenticator[i] = byte(0xa0 + i)
				}
				resp, err := ComputeCHAPResponse(1, tt.password, req.Authenticator[:])
				if err != nil {
					t.Fatalf("ComputeCHAPResponse: %v", err)
				}
				req.SetCHAPPassword(1, resp)
			}
			reply, err := client.Send(req)
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			if reply.Code != tt.want {
				t.Fatalf("code = %v, want %v", reply.Code, tt.want)
			}
		})
	}
}
