package radius

import (
	"net"
	"testing"
)

func TestPacketResilienceNoDictionary(t *testing.T) {
	// Save existing dictionary
	oldDict := GetDefaultDictionary()
	defer SetDefaultDictionary(oldDict)

	// Set an empty dictionary to force raw []byte decoding
	SetDefaultDictionary(NewDictionary())

	secret := "secret"
	pkg := Request(AccessRequest, secret)
	
	// Add attributes manually as raw bytes
	pkg.SetAVP(AVP{Type: AttrUserName, Value: []byte("testuser")})
	pkg.SetAVP(AVP{Type: AttrUserPassword, Value: avpPassword.Encode("testpass", secret, pkg.Authenticator[:])})
	pkg.SetAVP(AVP{Type: AttrNASIPAddress, Value: net.ParseIP("1.2.3.4").To4()})
	pkg.SetAVP(AVP{Type: AttrNASPort, Value: []byte{0, 0, 0, 80}})
	pkg.SetAVP(AVP{Type: AttrAcctSessionId, Value: []byte("session-123")})
	pkg.SetAVP(AVP{Type: AttrAcctStatusType, Value: []byte{0, 0, 0, 1}}) // Start

	// These calls would have panicked before the fix because Decode would return []byte
	// and the code was doing pkg.Decode(p).(string) or similar.

	if pkg.GetUsername() != "testuser" {
		t.Errorf("GetUsername failed, expected 'testuser', got '%s'", pkg.GetUsername())
	}

	if pkg.GetPassword() != "testpass" {
		t.Errorf("GetPassword failed, expected 'testpass', got '%s'", pkg.GetPassword())
	}

	if !pkg.GetNasIpAddress().Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("GetNasIpAddress failed, expected '1.2.3.4', got '%s'", pkg.GetNasIpAddress())
	}

	if pkg.GetNASPort() != 80 {
		t.Errorf("GetNASPort failed, expected 80, got %d", pkg.GetNASPort())
	}

	if pkg.GetAcctSessionId() != "session-123" {
		t.Errorf("GetAcctSessionId failed, expected 'session-123', got '%s'", pkg.GetAcctSessionId())
	}

	if pkg.GetAcctStatusType() != AcctStatusTypeEnumStart {
		t.Errorf("GetAcctStatusType failed, expected 1 (Start), got %d", pkg.GetAcctStatusType())
	}
}
