package radius

import (
	"bytes"
	_ "crypto/md5"
	"net"
	"testing"
)

func TestPacket(t *testing.T) {
	pac := Request(AccessRequest, "secret")
	pac.Identifier = 1
	copy(pac.Authenticator[:], []byte{0x13, 0x18, 0x57, 0x18, 0x29, 0xc1, 0x7b, 0x2f,
		0x9e, 0x28, 0x1d, 0x48, 0x67, 0x21, 0x0a, 0x71})

	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPortType, Value: []byte{0, 0, 0, 2}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrServiceType, Value: []byte{0, 0, 0, 2}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPort, Value: []byte{0, 0, 0, 1}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPortId, Value: []byte("NAS-Identifier")})

	pac.AVPs = append(pac.AVPs, AVP{Type: AttrCalledStationId, Value: []byte("1")})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrCallingStationId, Value: []byte("2")})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASIdentifier, Value: []byte("N")})

	pac.Encode()

	if pac.GetNASPortType() != NASPortTypeEnumISDNSync {
		t.Error("NASPortTypeEnum mismatch")
	}
	if pac.GetServiceType() != ServiceTypeEnumFramed {
		t.Error("ServiceTypeEnum mismatch")
	}
	if pac.GetAVP(AttrNASPort).Decode(pac).(uint32) != 1 {
		t.Error("NASPort mismatch")
	}
	if pac.GetAVP(AttrNASPortId).Decode(pac).(string) != "NAS-Identifier" {
		t.Error("NASPortId mismatch")
	}

	if pac.GetAVP(AttrCalledStationId).Value[0] != '1' {
		t.Error("CalledStationId mismatch")
	}
	if pac.GetAVP(AttrCallingStationId).Value[0] != '2' {
		t.Error("CallingStationId mismatch")
	}
	if pac.GetAVP(AttrNASIdentifier).Value[0] != 'N' {
		t.Error("NASIdentifier mismatch")
	}

	expectedHMAC := []byte{0x22, 0x9d, 0x20, 0x2f, 0xce, 0xf9, 0x60, 0x09,
		0xbc, 0x8a, 0x2c, 0x2a, 0xdb, 0x8b, 0x88, 0xfa}

	actualHMAC := pac.GetAVP(AttrMessageAuthenticator).Decode(pac).([]byte)
	if !bytes.Equal(actualHMAC, expectedHMAC) {
		t.Errorf("MessageAuthenticator mismatch:\nWant: %x\nGot : %x", expectedHMAC, actualHMAC)
	}

	// Verify p.Authenticator
	if !bytes.Equal(pac.Authenticator[:], []byte{0x13, 0x18, 0x57, 0x18, 0x29, 0xc1, 0x7b, 0x2f,
		0x9e, 0x28, 0x1d, 0x48, 0x67, 0x21, 0x0a, 0x71}) {
		t.Error("Authenticator mismatch")
	}

	// re-encode and check Message-Authenticator
	pac.Secret = "secret"
	pac.Encode()
	if !bytes.Equal(pac.GetAVP(AttrMessageAuthenticator).Decode(pac).([]byte), expectedHMAC) {
		t.Error("MessageAuthenticator mismatch after re-encode")
	}
}

func TestVerifyPacket(t *testing.T) {
	secret := "secret"
	pac := Request(AccessRequest, secret)
	pac.Identifier = 1
	copy(pac.Authenticator[:], []byte{0x13, 0x18, 0x57, 0x18, 0x29, 0xc1, 0x7b, 0x2f,
		0x9e, 0x28, 0x1d, 0x48, 0x67, 0x21, 0x0a, 0x71})

	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPortType, Value: []byte{0, 0, 0, 2}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrServiceType, Value: []byte{0, 0, 0, 2}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPort, Value: []byte{0, 0, 0, 1}})
	pac.AVPs = append(pac.AVPs, AVP{Type: AttrNASPortId, Value: []byte("NAS-Identifier")})

	buf, err := pac.Encode()
	if err != nil {
		t.Fatal(err)
	}

	pac2, err := DecodeRequest(secret, buf)
	if err != nil {
		t.Fatal(err)
	}
	if pac2.Identifier != 1 {
		t.Error("Identifier mismatch")
	}
}

func TestResponseAuthenticator(t *testing.T) {
	secret := "secret"
	pac := Request(AccessRequest, secret)
	pac.Identifier = 1
	copy(pac.Authenticator[:], []byte{0x13, 0x18, 0x57, 0x18, 0x29, 0xc1, 0x7b, 0x2f,
		0x9e, 0x28, 0x1d, 0x48, 0x67, 0x21, 0x0a, 0x71})

	req_buf, _ := pac.Encode()

	reply := pac.Reply()
	reply.Code = AccessAccept
	reply.AVPs = append(reply.AVPs, AVP{Type: AttrReplyMessage, Value: []byte("hello")})

	reply_buf, err := reply.Encode()
	if err != nil {
		t.Fatal(err)
	}

	reply2, err := DecodeReply(secret, reply_buf, pac.Authenticator[:])
	if err != nil {
		t.Fatalf("reply decode: %v", err)
	}
	if reply2.Code != AccessAccept {
		t.Error("Code mismatch")
	}

	// test bad secret
	_, err = DecodeReply("bad-secret", reply_buf, pac.Authenticator[:])
	if err != ErrAuthenticatorCheckFail {
		t.Error("Bad secret check failed")
	}

	// test bad request authenticator
	bad_req_auth := make([]byte, 16)
	_, err = DecodeReply(secret, reply_buf, bad_req_auth)
	if err != ErrAuthenticatorCheckFail {
		t.Error("Bad request auth check failed")
	}

	// test if it can decode with original req_buf
	reply3, err := DecodeReply(secret, reply_buf, req_buf[4:20])
	if err != nil {
		t.Fatal(err)
	}
	if reply3.Code != AccessAccept {
		t.Error("Code mismatch 3")
	}
}

func TestPacketGolden(t *testing.T) {
	inBytes := []byte{0x1, 0xef, 0x0, 0x8e, 0x94, 0xb, 0x18, 0xaf, 0xa, 0xb6, 0x12, 0xf5, 0x24, 0x4, 0x94, 0xbe, 0x18, 0xbc, 0x7, 0x4d,
		0x1, 0x4, 0x72, 0x48, 0x3d, 0x6, 0x0, 0x0, 0x0, 0x5, 0x6, 0x6, 0x0, 0x0, 0x0, 0x2, 0x5, 0x6, 0x0, 0x0, 0x0, 0x10, 0x57,
		0xf, 0x69, 0x6f, 0x73, 0x5f, 0x78, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x70, 0x73, 0x6b, 0x4, 0x6, 0xa, 0x1, 0x1, 0x5, 0x1e,
		0xf, 0x31, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x35, 0x5b, 0x35, 0x30, 0x30, 0x5d, 0x1f, 0x10, 0x31, 0x30, 0x2e, 0x31,
		0x2e, 0x31, 0x2e, 0x37, 0x30, 0x5b, 0x35, 0x30, 0x30, 0x5d, 0x20, 0xc, 0x73, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x53, 0x77,
		0x61, 0x6e, 0x2, 0x12, 0x8d, 0x7, 0xc2, 0xc0, 0xa4, 0x2, 0x2c, 0xed, 0x8e, 0x69, 0x5b, 0x9e, 0x25, 0x77, 0xe5, 0xd, 0x50,
		0x12, 0x39, 0x5c, 0xaa, 0x3e, 0x6d, 0x23, 0xea, 0xb5, 0x86, 0xc1, 0x3, 0x2d, 0x9d, 0x5c, 0x19, 0xca}
	pac, err := DecodeRequest("sEcReT", inBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pac.GetUsername() != "rH" {
		t.Errorf("Username mismatch: got %s, want rH", pac.GetUsername())
	}
	if pac.GetNASPortType() != NASPortTypeEnumVirtual {
		t.Errorf("NASPortType mismatch")
	}
	if pac.GetServiceType() != ServiceTypeEnumFramed {
		t.Errorf("ServiceType mismatch")
	}
	if pac.GetNASPort() != 16 {
		t.Errorf("NASPort mismatch: got %d, want 16", pac.GetNASPort())
	}
	if pac.GetNASIdentifier() != "strongSwan" {
		t.Errorf("NASIdentifier mismatch: got %s, want strongSwan", pac.GetNASIdentifier())
	}
	if !pac.GetNasIpAddress().Equal(net.ParseIP("10.1.1.5")) {
		t.Errorf("NASIPAddress mismatch: got %v, want 10.1.1.5", pac.GetNasIpAddress())
	}

	expectedHMAC := []byte{0x39, 0x5c, 0xaa, 0x3e, 0x6d, 0x23, 0xea, 0xb5, 0x86, 0xc1, 0x3, 0x2d, 0x9d, 0x5c, 0x19, 0xca}
	actualHMAC := pac.GetAVP(AttrMessageAuthenticator).Decode(pac).([]byte)
	if !bytes.Equal(actualHMAC, expectedHMAC) {
		t.Errorf("MessageAuthenticator mismatch:\nWant: %x\nGot : %x", expectedHMAC, actualHMAC)
	}
}

func TestPacketEAPGolden(t *testing.T) {
	inBytes := []byte{0x1, 0xe6, 0x0, 0xa5, 0xe6, 0x17, 0x46, 0x35, 0xe4, 0xba, 0x8f, 0xe5, 0x15, 0x90, 0x96, 0x33, 0xd0,
		0xb3, 0x61, 0x34, 0x1, 0x12, 0x63, 0x62, 0x46, 0x69, 0x42, 0x6f, 0x6f, 0x52, 0x6e, 0x5a, 0x73, 0x58, 0x6e,
		0x5a, 0x4a, 0x33, 0x3d, 0x6, 0x0, 0x0, 0x0, 0x5, 0x6, 0x6, 0x0, 0x0, 0x0, 0x2, 0x5, 0x6, 0x0, 0x0, 0x0, 0xa,
		0x57, 0x13, 0x69, 0x6f, 0x73, 0x5f, 0x69, 0x6b, 0x65, 0x76, 0x32, 0x5f, 0x65, 0x61, 0x70, 0x5f, 0x70, 0x73,
		0x6b, 0x4, 0x6, 0xa, 0x1, 0x1, 0x5, 0x1e, 0xf, 0x31, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x35, 0x5b, 0x35,
		0x30, 0x30, 0x5d, 0x1f, 0x10, 0x31, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x36, 0x36, 0x5b, 0x35, 0x30, 0x30,
		0x5d, 0x4f, 0x17, 0x2, 0x0, 0x0, 0x15, 0x1, 0x63, 0x62, 0x46, 0x69, 0x42, 0x6f, 0x6f, 0x52, 0x6e, 0x5a, 0x73,
		0x58, 0x6e, 0x5a, 0x4a, 0x33, 0x20, 0xc, 0x73, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x53, 0x77, 0x61, 0x6e, 0x50,
		0x12, 0x48, 0x14, 0x43, 0xf2, 0x6, 0xa4, 0x8b, 0x7a, 0xd8, 0xc0, 0xdd, 0xe9, 0xb3, 0x3, 0x7d, 0x84}
	pac, err := DecodeRequest("sEcReT", inBytes)
	if err != nil {
		t.Fatal(err)
	}
	if pac.GetUsername() != "cbFiBooRnZsXnZJ3" {
		t.Errorf("Username mismatch: got %s, want cbFiBooRnZsXnZJ3", pac.GetUsername())
	}
	eap := pac.GetEAPMessage()
	if eap == nil {
		t.Fatal("EAP message is nil")
	}
	if eap.Code != EapCodeResponse {
		t.Errorf("EAP code mismatch: got %v, want %v", eap.Code, EapCodeResponse)
	}
	if eap.Type != EapTypeIdentity {
		t.Errorf("EAP type mismatch: got %v, want %v", eap.Type, EapTypeIdentity)
	}
	if string(eap.Data) != "cbFiBooRnZsXnZJ3" {
		t.Errorf("EAP data mismatch: got %s, want cbFiBooRnZsXnZJ3", string(eap.Data))
	}
}
