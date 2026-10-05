package radius

import (
	"bytes"
	"testing"
)

func TestEapDecodeSuccess(t *testing.T) {
	// EAP-Success: Code=3, ID=42, Length=4 (no Type, no Data)
	b := []byte{0x03, 0x2a, 0x00, 0x04}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode returned error for Success: %v", err)
	}
	if eap.Code != EapCodeSuccess {
		t.Errorf("Code: got %v, want %v", eap.Code, EapCodeSuccess)
	}
	if eap.Identifier != 42 {
		t.Errorf("Identifier: got %d, want 42", eap.Identifier)
	}
	if eap.Type != 0 {
		t.Errorf("Type should be zero for Success, got %v", eap.Type)
	}
	if len(eap.Data) != 0 {
		t.Errorf("Data should be empty for Success, got %v", eap.Data)
	}
}

func TestEapDecodeFailure(t *testing.T) {
	// EAP-Failure: Code=4, ID=7, Length=4
	b := []byte{0x04, 0x07, 0x00, 0x04}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode returned error for Failure: %v", err)
	}
	if eap.Code != EapCodeFailure {
		t.Errorf("Code: got %v, want %v", eap.Code, EapCodeFailure)
	}
	if eap.Identifier != 7 {
		t.Errorf("Identifier: got %d, want 7", eap.Identifier)
	}
}

func TestEapEncodeSuccess(t *testing.T) {
	eap := &EapPacket{Code: EapCodeSuccess, Identifier: 42}
	b := eap.Encode()
	if len(b) != 4 {
		t.Fatalf("Encode length: got %d, want 4", len(b))
	}
	if b[0] != 0x03 || b[1] != 0x2a || b[2] != 0x00 || b[3] != 0x04 {
		t.Errorf("Encode bytes: got %v, want [03 2a 00 04]", b)
	}
}

func TestEapEncodeFailure(t *testing.T) {
	eap := &EapPacket{Code: EapCodeFailure, Identifier: 7}
	b := eap.Encode()
	if len(b) != 4 {
		t.Fatalf("Encode length: got %d, want 4", len(b))
	}
	if b[0] != 0x04 || b[1] != 0x07 || b[2] != 0x00 || b[3] != 0x04 {
		t.Errorf("Encode bytes: got %v, want [04 07 00 04]", b)
	}
}

func TestEapSuccessRoundTrip(t *testing.T) {
	orig := &EapPacket{Code: EapCodeSuccess, Identifier: 99}
	decoded, err := EapDecode(orig.Encode())
	if err != nil {
		t.Fatalf("round-trip decode error: %v", err)
	}
	if decoded.Code != orig.Code || decoded.Identifier != orig.Identifier {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestEapFailureRoundTrip(t *testing.T) {
	orig := &EapPacket{Code: EapCodeFailure, Identifier: 1}
	decoded, err := EapDecode(orig.Encode())
	if err != nil {
		t.Fatalf("round-trip decode error: %v", err)
	}
	if decoded.Code != orig.Code || decoded.Identifier != orig.Identifier {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestEapSuccessString(t *testing.T) {
	eap := &EapPacket{Code: EapCodeSuccess, Identifier: 5}
	s := eap.String()
	if s != "Eap Code:Success id:5" {
		t.Errorf("String: got %q, want %q", s, "Eap Code:Success id:5")
	}
}

func TestEapDecodeTooShort(t *testing.T) {
	cases := [][]byte{
		{},
		{0x03},
		{0x03, 0x01},
		{0x03, 0x01, 0x00},
	}
	for _, b := range cases {
		_, err := EapDecode(b)
		if err == nil {
			t.Errorf("expected error for input %v, got nil", b)
		}
	}
}

func TestEapDecodeRequestIdentity(t *testing.T) {
	// EAP-Request/Identity: Code=1, ID=1, Length=5, Type=1, no data
	// Typical server challenge: "please identify yourself"
	b := []byte{0x01, 0x01, 0x00, 0x05, 0x01}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if eap.Code != EapCodeRequest {
		t.Errorf("Code: got %v, want %v", eap.Code, EapCodeRequest)
	}
	if eap.Identifier != 1 {
		t.Errorf("Identifier: got %d, want 1", eap.Identifier)
	}
	if eap.Type != EapTypeIdentity {
		t.Errorf("Type: got %v, want %v", eap.Type, EapTypeIdentity)
	}
	if len(eap.Data) != 0 {
		t.Errorf("Data: got %v, want empty", eap.Data)
	}
}

func TestEapDecodeResponseIdentity(t *testing.T) {
	// EAP-Response/Identity: Code=2, ID=1, Length=21, Type=1, Data="user@example.com"
	identity := "user@example.com"
	b := []byte{0x02, 0x01, 0x00, 0x15, 0x01}
	b = append(b, []byte(identity)...)
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if eap.Code != EapCodeResponse {
		t.Errorf("Code: got %v, want %v", eap.Code, EapCodeResponse)
	}
	if eap.Type != EapTypeIdentity {
		t.Errorf("Type: got %v, want %v", eap.Type, EapTypeIdentity)
	}
	if string(eap.Data) != identity {
		t.Errorf("Data: got %q, want %q", string(eap.Data), identity)
	}
}

func TestEapDecodeResponseNak(t *testing.T) {
	// EAP-Response/Nak: Code=2, ID=2, Length=6, Type=3, Data=[26] (request MSCHAPv2)
	b := []byte{0x02, 0x02, 0x00, 0x06, 0x03, 0x1a}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if eap.Code != EapCodeResponse {
		t.Errorf("Code: got %v, want %v", eap.Code, EapCodeResponse)
	}
	if eap.Type != EapTypeNak {
		t.Errorf("Type: got %v, want %v", eap.Type, EapTypeNak)
	}
	if len(eap.Data) != 1 || eap.Data[0] != 0x1a {
		t.Errorf("Data: got %v, want [0x1a]", eap.Data)
	}
}

func TestEapDecodeRequestMD5Challenge(t *testing.T) {
	// EAP-Request/MD5-Challenge: Code=1, ID=3, Type=4
	// Data: value-size(1) + challenge(16) + name
	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}
	name := []byte("nas1")
	data := append([]byte{byte(len(challenge))}, challenge...)
	data = append(data, name...)
	pkt := &EapPacket{Code: EapCodeRequest, Identifier: 3, Type: EapTypeMd5Challenge, Data: data}
	decoded, err := EapDecode(pkt.Encode())
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if decoded.Type != EapTypeMd5Challenge {
		t.Errorf("Type: got %v, want %v", decoded.Type, EapTypeMd5Challenge)
	}
	if string(decoded.Data) != string(data) {
		t.Errorf("Data mismatch")
	}
}

func TestEapRequestResponseRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		pkt  *EapPacket
	}{
		{
			name: "Request/Identity no data",
			pkt:  &EapPacket{Code: EapCodeRequest, Identifier: 1, Type: EapTypeIdentity},
		},
		{
			name: "Response/Identity with data",
			pkt:  &EapPacket{Code: EapCodeResponse, Identifier: 1, Type: EapTypeIdentity, Data: []byte("alice")},
		},
		{
			name: "Response/Nak",
			pkt:  &EapPacket{Code: EapCodeResponse, Identifier: 2, Type: EapTypeNak, Data: []byte{byte(EapTypeMSCHAPV2)}},
		},
		{
			name: "Request/Notification",
			pkt:  &EapPacket{Code: EapCodeRequest, Identifier: 5, Type: EapTypeNotification, Data: []byte("password expired")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := EapDecode(tc.pkt.Encode())
			if err != nil {
				t.Fatalf("EapDecode error: %v", err)
			}
			if decoded.Code != tc.pkt.Code {
				t.Errorf("Code: got %v, want %v", decoded.Code, tc.pkt.Code)
			}
			if decoded.Identifier != tc.pkt.Identifier {
				t.Errorf("Identifier: got %d, want %d", decoded.Identifier, tc.pkt.Identifier)
			}
			if decoded.Type != tc.pkt.Type {
				t.Errorf("Type: got %v, want %v", decoded.Type, tc.pkt.Type)
			}
			if string(decoded.Data) != string(tc.pkt.Data) {
				t.Errorf("Data: got %v, want %v", decoded.Data, tc.pkt.Data)
			}
		})
	}
}

func TestEapRequestString(t *testing.T) {
	eap := &EapPacket{Code: EapCodeRequest, Identifier: 1, Type: EapTypeIdentity}
	s := eap.String()
	if s != `Eap Code:Request id:1 Type:Identity Data:[""]` {
		t.Errorf("String: got %q", s)
	}
}

func TestEapLengthFieldTruncatesData(t *testing.T) {
	// Length field says 6 but buffer is longer — only 1 byte of data should be read
	// Code=2, ID=1, Length=6, Type=1, Data[0]=0xAA, extra=0xBB (should be ignored)
	b := []byte{0x02, 0x01, 0x00, 0x06, 0x01, 0xaa, 0xbb}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if len(eap.Data) != 1 || eap.Data[0] != 0xaa {
		t.Errorf("Data: got %v, want [0xaa]", eap.Data)
	}
}

func TestEapDecodeRequestResponseTooShort(t *testing.T) {
	// Request/Response with Length=4 (no Type byte) should be an error
	b := []byte{0x01, 0x01, 0x00, 0x04}
	_, err := EapDecode(b)
	if err == nil {
		t.Error("expected error for Request with Length=4, got nil")
	}
}

func TestEapDecodeBadLength(t *testing.T) {
	cases := map[string][]byte{
		"length below header":     {0x02, 0x01, 0x00, 0x03, 0x01},
		"length past buffer":      {0x02, 0x01, 0x00, 0x08, 0x01, 0xaa},
		"success past buffer":     {0x03, 0x01, 0x00, 0x05},
		"expanded type too short": {0x02, 0x01, 0x00, 0x08, 0xfe, 0x00, 0x00, 0x00},
	}
	for name, b := range cases {
		if eap, err := EapDecode(b); err == nil {
			t.Errorf("%s: expected error, got %+v", name, eap)
		}
	}
}

func TestEapDecodeExpandedType(t *testing.T) {
	// Expanded Type: Type=254, Vendor-Id=0, Vendor-Type=1
	b := []byte{0x02, 0x01, 0x00, 0x0c, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	eap, err := EapDecode(b)
	if err != nil {
		t.Fatalf("EapDecode error: %v", err)
	}
	if eap.Type != EapTypeExpandedTypes || len(eap.Data) != 7 {
		t.Errorf("got %+v", eap)
	}
}

func TestEapToEAPMessagesSplit(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 600)
	eap := &EapPacket{Code: EapCodeRequest, Identifier: 3, Type: EapTypeMSCHAPV2, Data: data}
	avps := eap.ToEAPMessages()
	if len(avps) != 3 {
		t.Fatalf("got %d AVPs, want 3", len(avps))
	}
	var joined []byte
	for _, a := range avps {
		if a.Type != AttrEAPMessage || len(a.Value) > maxAVPValueLen {
			t.Errorf("bad fragment: type %d len %d", a.Type, len(a.Value))
		}
		joined = append(joined, a.Value...)
	}
	if !bytes.Equal(joined, eap.Encode()) {
		t.Error("fragments do not reassemble to the encoded packet")
	}
}

func TestSetEAPMessageRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 1000)
	eap := &EapPacket{Code: EapCodeResponse, Identifier: 9, Type: EapTypeMd5Challenge, Data: data}

	req := Request(AccessRequest, "secret")
	// stale two-fragment EAP-Message must be fully replaced
	req.AddAVP(AVP{Type: AttrEAPMessage, Value: []byte{0x02, 0x00}})
	req.AddAVP(AVP{Type: AttrUserName, Value: []byte("bob")})
	req.AddAVP(AVP{Type: AttrEAPMessage, Value: []byte{0x00, 0x05, 0x01}})
	req.SetEAPMessage(eap)

	buf, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoders := map[string]func() (*Packet, error){
		"DecodeRequest":     func() (*Packet, error) { return DecodeRequest("secret", buf) },
		"DecodeRequestLazy": func() (*Packet, error) { return DecodeRequestLazy("secret", buf) },
	}
	for name, decode := range decoders {
		p, err := decode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := p.GetEAPMessage()
		if got == nil {
			t.Fatalf("%s: GetEAPMessage returned nil", name)
		}
		if got.Code != eap.Code || got.Identifier != eap.Identifier || got.Type != eap.Type || !bytes.Equal(got.Data, data) {
			t.Errorf("%s: got code %v id %d type %v len %d", name, got.Code, got.Identifier, got.Type, len(got.Data))
		}
		if p.GetUsername() != "bob" {
			t.Errorf("%s: User-Name lost", name)
		}
	}
}

func TestAvpEapMessageFragmentFallback(t *testing.T) {
	frag := AVP{Type: AttrEAPMessage, Value: []byte{0x02, 0x01, 0x01, 0x00, 0x01, 0xaa}}
	v, ok := frag.Decode(nil).([]byte)
	if !ok || !bytes.Equal(v, frag.Value) {
		t.Errorf("Decode = %#v, want raw bytes", frag.Decode(nil))
	}
	want := "AVP type: EAP-Message []byte{0x2, 0x1, 0x1, 0x0, 0x1, 0xaa}"
	if s := frag.String(); s != want {
		t.Errorf("String = %q, want %q", s, want)
	}
}

func TestAvpEapMessageValue(t *testing.T) {
	eap := &EapPacket{Code: EapCodeResponse, Identifier: 1, Type: EapTypeIdentity, Data: []byte("u")}
	got, ok := eap.ToEAPMessage().Decode(nil).(*EapPacket)
	if !ok || got.Type != EapTypeIdentity || string(got.Data) != "u" {
		t.Errorf("Decode = %#v", got)
	}
}
