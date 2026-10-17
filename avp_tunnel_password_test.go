package radius

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Tag 1, salt 0x8123, "tunnel-pass", secret "testing123", Request Authenticator 00..0f
// (computed independently, RFC 2868 section 3.5); in an Access-Accept to that request.
const tunnelPasswordVector = "01812379529da6b23e3aa2fbb16e08eeba8f83"

func tunnelPasswordVectorPacket(t *testing.T) (*Packet, AVP) {
	t.Helper()
	v, err := hex.DecodeString(tunnelPasswordVector)
	if err != nil {
		t.Fatal(err)
	}
	p := &Packet{Secret: "testing123", Code: AccessAccept}
	for i := range p.requestAuth {
		p.requestAuth[i] = byte(i)
	}
	a := AVP{Type: AttrTunnelPassword, Value: v}
	p.AddAVP(a)
	return p, a
}

func TestTunnelPasswordDecodeVector(t *testing.T) {
	check := func(t *testing.T, d *Dictionary) {
		p, a := tunnelPasswordVectorPacket(t)
		if got := a.Decode(p); got != "tunnel-pass" {
			t.Errorf("Decode = %#v, want %q", got, "tunnel-pass")
		}
		if got := d.DecodeAVPValue(p, a); got != "tunnel-pass" {
			t.Errorf("DecodeAVPValue = %q, want %q", got, "tunnel-pass")
		}
	}
	t.Run("builtin", func(t *testing.T) { check(t, GetDefaultDictionary()) })
	t.Run("freeradius", func(t *testing.T) { check(t, useFreeRADIUSFlagsDict(t)) })
}

func TestTunnelPasswordEncryptVector(t *testing.T) {
	ra := make([]byte, authenticatorLen)
	for i := range ra {
		ra[i] = byte(i)
	}
	got := tunnelPasswordEncrypt(1, [tunnelSaltLen]byte{0x81, 0x23}, "tunnel-pass", "testing123", ra)
	if hex.EncodeToString(got) != tunnelPasswordVector {
		t.Errorf("encrypt = %x, want %s", got, tunnelPasswordVector)
	}
}

// Tunnel-Password in an Access-Accept is encrypted with the Request Authenticator.
func TestTunnelPasswordReplyRoundTrip(t *testing.T) {
	const secret = "testing123"
	long := strings.Repeat("x", tunnelPasswordMaxLen)

	for _, pw := range []string{"", "vlan-secret", strings.Repeat("y", 15), strings.Repeat("z", 16), long} {
		req := Request(AccessRequest, secret)
		reply := req.ReplyAccept()
		if err := reply.AddTunnelPassword(3, pw); err != nil {
			t.Fatalf("AddTunnelPassword(%d bytes): %v", len(pw), err)
		}
		a := reply.GetAVP(AttrTunnelPassword)
		if a.Value[tunnelTagLen]&tunnelSaltBit == 0 {
			t.Errorf("salt high bit not set: %x", a.Value[:tunnelHeaderLen])
		}
		b, err := reply.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		got, err := DecodeReply(secret, b, req.Authenticator[:])
		if err != nil {
			t.Fatalf("DecodeReply: %v", err)
		}
		tag, password, ok := got.GetTunnelPassword()
		if !ok || tag != 3 || password != pw {
			t.Errorf("GetTunnelPassword = %d, %q, %v; want 3, %q, true", tag, password, ok, pw)
		}
	}

	if err := Request(AccessRequest, secret).ReplyAccept().AddTunnelPassword(0, long+"x"); !errors.Is(err, ErrTunnelPasswordTooLong) {
		t.Errorf("too long: err = %v, want ErrTunnelPasswordTooLong", err)
	}
}

func TestTunnelPasswordTemplateAndParse(t *testing.T) {
	const secret = "testing123"
	d := GetDefaultDictionary()

	if _, err := d.ParseAVP("Tunnel-Password", "x"); !errors.Is(err, ErrEncryptedAttribute) {
		t.Errorf("ParseAVP: err = %v, want ErrEncryptedAttribute", err)
	}

	rt, err := d.CreateRequestTemplate(AccessAccept, "Tunnel-Password")
	if err != nil {
		t.Fatalf("CreateRequestTemplate: %v", err)
	}
	req := Request(AccessRequest, secret)
	reply := req.ReplyAccept()
	rt.Fill(reply, "from-template")
	b, err := reply.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeReply(secret, b, req.Authenticator[:])
	if err != nil {
		t.Fatalf("DecodeReply: %v", err)
	}
	if _, password, ok := got.GetTunnelPassword(); !ok || password != "from-template" {
		t.Errorf("GetTunnelPassword = %q, %v; want %q", password, ok, "from-template")
	}
}

func TestTunnelPasswordMalformed(t *testing.T) {
	p := &Packet{Secret: "s"}
	for _, v := range [][]byte{nil, {1, 0x80, 0}, make([]byte, tunnelHeaderLen+blockSize-1), make([]byte, tunnelHeaderLen+blockSize+1)} {
		if _, _, ok := avpTunnelPassword.decrypt(p, v); ok {
			t.Errorf("decrypt(%d bytes) ok, want failure", len(v))
		}
	}
}

// zeroAuthRequestCodes hide attributes with an all-zero authenticator (RFC 2866, 5176; FreeRADIUS).
var zeroAuthRequestCodes = []PacketCode{AccountingRequest, CoARequest, DisconnectRequest}

// replyCodes are the reply packet codes.
var replyCodes = []PacketCode{AccessAccept, AccessReject, AccessChallenge, AccountingResponse,
	CoAAccept, CoAReject, DisconnectAccept, DisconnectReject}

// The sender reads its own encoded request, and the receiver decodes it, with the zero authenticator.
func TestTunnelPasswordZeroAuthenticatorRequest(t *testing.T) {
	const secret, tag, pw = "testing123", 1, "tp"
	for _, code := range zeroAuthRequestCodes {
		p := Request(code, secret)
		p.Authenticator[0] = 1 // ignored for hiding
		if err := p.AddTunnelPassword(tag, pw); err != nil {
			t.Fatal(err)
		}
		b, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeRequest(secret, b)
		if err != nil {
			t.Fatal(err)
		}
		for which, q := range map[string]*Packet{"sender": p, "receiver": got} {
			if gotTag, gotPW, ok := q.GetTunnelPassword(); !ok || gotTag != tag || gotPW != pw {
				t.Errorf("%v %s: Tunnel-Password = %d %q %v", code, which, gotTag, gotPW, ok)
			}
			if s := q.String(); !strings.Contains(s, "Tunnel-Password "+pw) {
				t.Errorf("%v %s: String = %q", code, which, s)
			}
		}
	}
}

// A reply not built with Reply() has no request authenticator, so it can't hide values (FreeRADIUS).
func TestTunnelPasswordReplyWithoutRequest(t *testing.T) {
	const secret = "testing123"
	tmpl, err := GetDefaultDictionary().GetTemplate("Tunnel-Password")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range replyCodes {
		p := &Packet{Code: code, Secret: secret}
		if err := p.AddTunnelPassword(0, "tp"); !errors.Is(err, ErrNoRequestAuthenticator) {
			t.Errorf("%v: AddTunnelPassword err = %v", code, err)
		}
		tmpl.Add(p, "tp")
		if len(p.AVPs) != 0 {
			t.Errorf("%v: AVPs added: %v", code, p.AVPs)
		}

		r := Request(AccessRequest, secret).Reply()
		r.Code = code
		if err := r.AddTunnelPassword(0, "tp"); err != nil {
			t.Errorf("%v: Reply().AddTunnelPassword: %v", code, err)
		}
	}
}

// Tunnel-Password can't be hidden in an Access-Request or Status-Server (RFC 2868 section 3.5, FreeRADIUS).
func TestTunnelPasswordInAccessRequest(t *testing.T) {
	const secret = "testing123"
	d := loadTLVDict(t, encTLVDict)
	tmpl, err := GetDefaultDictionary().GetTemplate("Tunnel-Password")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []PacketCode{AccessRequest, StatusServer} {
		packets := map[string]*Packet{"Request": Request(code, secret), "manual": {Code: code, Secret: secret}}
		for which, p := range packets {
			auth := p.Authenticator
			if err := p.AddTunnelPassword(0, "tp"); !errors.Is(err, ErrTunnelPasswordInRequest) {
				t.Errorf("%v %s: AddTunnelPassword err = %v", code, which, err)
			}
			if err := addTLV(d, p, "", "Enc-TLV", tlvValue{Name: "Enc-Pass", Value: "pw"}, tlvValue{Name: "Enc-Key", Value: "k"}); !errors.Is(err, ErrTunnelPasswordInRequest) {
				t.Errorf("%v %s: AddTLV err = %v", code, which, err)
			}
			tmpl.Add(p, "tp")
			if len(p.AVPs) != 0 || p.Authenticator != auth {
				t.Errorf("%v %s: packet changed: AVPs %v, authenticator %x", code, which, p.AVPs, p.Authenticator)
			}
		}
	}
}

// A received Access-Request's encrypt=2 values are decrypted with zeros, as FreeRADIUS does.
func TestTunnelPasswordDecodeAccessRequest(t *testing.T) {
	const secret, tag, pw = "testing123", 1, "tp"
	d := loadTLVDict(t, encTLVDict)
	salt, err := newTunnelSalt()
	if err != nil {
		t.Fatal(err)
	}
	p := Request(AccessRequest, secret)
	p.AddAVP(AVP{Type: AttrTunnelPassword, Value: tunnelPasswordEncrypt(tag, salt, pw, secret, zeroAuthenticator[:])})
	key := tunnelPasswordEncrypt(0, salt, pw, secret, zeroAuthenticator[:])[tunnelTagLen:]
	p.AddAVP(AVP{Type: encTLVType, Value: append([]byte{2, byte(tlvHeaderLen + len(key))}, key...)})
	b, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(secret, b)
	if err != nil {
		t.Fatal(err)
	}
	if gotTag, gotPW, ok := got.GetTunnelPassword(); !ok || gotTag != tag || gotPW != pw {
		t.Errorf("Tunnel-Password = %d %q %v", gotTag, gotPW, ok)
	}
	if v, ok := d.GetTLV(got, "", "Enc-Key"); !ok || string(v) != pw {
		t.Errorf("Enc-Key = %q, %v", v, ok)
	}
}
