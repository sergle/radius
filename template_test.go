package radius

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

func TestRequestTemplateGolden(t *testing.T) {
	const secret = "s3cr3t"

	// Load builtin dictionary and register a test vendor for the VSA slot.
	dict := NewDictionary()
	dict.loadFileInternal("dictionary.builtin")
	vf := t.TempDir() + "/vendor.dict"
	os.WriteFile(vf, []byte("VENDOR TestVendor 9999\nBEGIN-VENDOR TestVendor\nATTRIBUTE Policy-Name 1 string\nEND-VENDOR TestVendor\n"), 0644)
	dict.loadFileInternal(vf)

	rt, err := dict.CreateRequestTemplate(AccountingRequest, "User-Name", "NAS-IP-Address", "NAS-Port")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.AddAttributes(dict, "Acct-Session-Id", "Called-Station-Id"); err != nil {
		t.Fatal(err)
	}
	if err := rt.AddVSAAttribute(dict, "TestVendor", "Policy-Name"); err != nil {
		t.Fatal(err)
	}
	rt.AddVLAN()

	// values order: User-Name, NAS-IP-Address, NAS-Port, Acct-Session-Id, Called-Station-Id, Policy-Name (VSA), VLAN
	tests := []struct {
		name   string
		values []string
		want   []byte
	}{
		{
			name:   "alice/corp/vlan100",
			values: []string{"alice", "10.0.0.1", "1", "sess-001", "00-11-22-33-44-55:corp", "corp-policy", "100"},
			want: []byte{
				0x04, 0x01, 0x00, 0x6d, 0x80, 0xd8, 0x87, 0x0f, 0x0c, 0x1e, 0x4a, 0x87, 0x62, 0x6a, 0x21, 0xf0,
				0x48, 0x4c, 0xb4, 0x5d, 0x01, 0x07, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x04, 0x06, 0x0a, 0x00, 0x00,
				0x01, 0x05, 0x06, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x2d, 0x30, 0x30,
				0x31, 0x1e, 0x18, 0x30, 0x30, 0x2d, 0x31, 0x31, 0x2d, 0x32, 0x32, 0x2d, 0x33, 0x33, 0x2d, 0x34,
				0x34, 0x2d, 0x35, 0x35, 0x3a, 0x63, 0x6f, 0x72, 0x70, 0x1a, 0x13, 0x00, 0x00, 0x27, 0x0f, 0x01,
				0x0d, 0x63, 0x6f, 0x72, 0x70, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x40, 0x06, 0x00, 0x00,
				0x00, 0x0d, 0x41, 0x06, 0x00, 0x00, 0x00, 0x06, 0x51, 0x05, 0x31, 0x30, 0x30,
			},
		},
		{
			name:   "bob/guest/vlan200",
			values: []string{"bob", "10.0.0.2", "2", "sess-002", "AA-BB-CC-DD-EE-FF:guest", "guest-policy", "200"},
			want: []byte{
				0x04, 0x01, 0x00, 0x6d, 0x7e, 0x86, 0x36, 0xbf, 0x10, 0xab, 0x7f, 0xee, 0xda, 0x48, 0x88, 0xd8,
				0xb6, 0x7a, 0x29, 0x87, 0x01, 0x05, 0x62, 0x6f, 0x62, 0x04, 0x06, 0x0a, 0x00, 0x00, 0x02, 0x05,
				0x06, 0x00, 0x00, 0x00, 0x02, 0x2c, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x2d, 0x30, 0x30, 0x32, 0x1e,
				0x19, 0x41, 0x41, 0x2d, 0x42, 0x42, 0x2d, 0x43, 0x43, 0x2d, 0x44, 0x44, 0x2d, 0x45, 0x45, 0x2d,
				0x46, 0x46, 0x3a, 0x67, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x14, 0x00, 0x00, 0x27, 0x0f, 0x01, 0x0e,
				0x67, 0x75, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x40, 0x06, 0x00, 0x00,
				0x00, 0x0d, 0x41, 0x06, 0x00, 0x00, 0x00, 0x06, 0x51, 0x05, 0x32, 0x30, 0x30,
			},
		},
		{
			name:   "carol/mgmt/vlan4094",
			values: []string{"carol", "192.168.1.1", "3", "sess-003", "FF-EE-DD-CC-BB-AA:mgmt", "mgmt-policy", "4094"},
			want: []byte{
				0x04, 0x01, 0x00, 0x6e, 0x56, 0xa4, 0x81, 0x0c, 0x2d, 0x8e, 0xa6, 0x27, 0x86, 0xbb, 0xe0, 0xa3,
				0xc7, 0x19, 0x42, 0xad, 0x01, 0x07, 0x63, 0x61, 0x72, 0x6f, 0x6c, 0x04, 0x06, 0xc0, 0xa8, 0x01,
				0x01, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03, 0x2c, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x2d, 0x30, 0x30,
				0x33, 0x1e, 0x18, 0x46, 0x46, 0x2d, 0x45, 0x45, 0x2d, 0x44, 0x44, 0x2d, 0x43, 0x43, 0x2d, 0x42,
				0x42, 0x2d, 0x41, 0x41, 0x3a, 0x6d, 0x67, 0x6d, 0x74, 0x1a, 0x13, 0x00, 0x00, 0x27, 0x0f, 0x01,
				0x0d, 0x6d, 0x67, 0x6d, 0x74, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x40, 0x06, 0x00, 0x00,
				0x00, 0x0d, 0x41, 0x06, 0x00, 0x00, 0x00, 0x06, 0x51, 0x06, 0x34, 0x30, 0x39, 0x34,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Packet{Code: AccountingRequest, Identifier: 1, Secret: secret}
			rt.Fill(p, tc.values...)
			got, err := p.Encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("encoding mismatch\ngot:  %x\nwant: %x", got, tc.want)
			}

			// round-trip: decode and verify key fields
			decoded, err := DecodeRequest(secret, got)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.GetUsername() != tc.values[0] {
				t.Errorf("User-Name: got %q, want %q", decoded.GetUsername(), tc.values[0])
			}
			vlanID, ok := decoded.GetVLAN()
			if !ok {
				t.Fatal("GetVLAN returned false after round-trip")
			}
			wantVLAN, _ := strconv.ParseUint(tc.values[6], 10, 16)
			if vlanID != uint16(wantVLAN) {
				t.Errorf("VLAN: got %d, want %d", vlanID, wantVLAN)
			}
		})
	}
}

func TestVLANTemplate(t *testing.T) {
	tmpl := &vlanTemplate{}

	t.Run("Add and Get round-trip", func(t *testing.T) {
		p := Request(AccessAccept, "secret")
		tmpl.Add(p, "200")
		id, ok := p.GetVLAN()
		if !ok {
			t.Fatal("Get returned false")
		}
		if id != 200 {
			t.Errorf("got %d, want 200", id)
		}
	})

	t.Run("Add invalid values is no-op", func(t *testing.T) {
		for _, v := range []string{"0", "4095", "abc", ""} {
			p := Request(AccessAccept, "secret")
			tmpl.Add(p, v)
			if _, ok := p.GetVLAN(); ok {
				t.Errorf("expected no-op for %q", v)
			}
		}
	})

	t.Run("Add boundary values", func(t *testing.T) {
		for _, id := range []uint16{1, 4094} {
			p := Request(AccessAccept, "secret")
			tmpl.Add(p, strconv.Itoa(int(id)))
			got, ok := p.GetVLAN()
			if !ok {
				t.Errorf("VLAN %d: Get returned false", id)
			}
			if got != id {
				t.Errorf("VLAN %d: got %d", id, got)
			}
		}
	})

	t.Run("implements AVPTemplate", func(t *testing.T) {
		var _ AVPTemplate = &vlanTemplate{}
	})
}

func TestTemplate(t *testing.T) {
	dict := GetDefaultDictionary()

	t.Run("GetTemplate", func(t *testing.T) {
		tmpl, err := dict.GetTemplate("User-Name")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if tmpl.attrType != AttrUserName {
			t.Errorf("Expected type %d, got %d", AttrUserName, tmpl.attrType)
		}
		if tmpl.handler != avpString {
			t.Errorf("Expected avpString handler")
		}
	})

	t.Run("GetTemplateNotFound", func(t *testing.T) {
		_, err := dict.GetTemplate("Non-Existent")
		if err == nil {
			t.Fatal("Expected error for non-existent attribute")
		}
	})

	t.Run("RequestTemplate", func(t *testing.T) {
		client := NewRadClient("127.0.0.1:1812", "secret")
		rt, err := dict.CreateRequestTemplate(AccessRequest, "User-Name", "User-Password")
		if err != nil {
			t.Fatalf("Failed to create RequestTemplate: %v", err)
		}

		req := rt.CreateRequest(client, "testuser", "testpass")
		if req.Code != AccessRequest {
			t.Errorf("Expected code %d, got %d", AccessRequest, req.Code)
		}

		// Verify User-Name
		un := req.GetAVP(AttrUserName)
		if un == nil {
			t.Fatal("User-Name AVP not found")
		}
		if string(un.Value) != "testuser" {
			t.Errorf("Expected 'testuser', got '%s'", string(un.Value))
		}

		// Verify User-Password (should be encrypted, not raw)
		up := req.GetAVP(AttrUserPassword)
		if up == nil {
			t.Fatal("User-Password AVP not found")
		}
		if bytes.Equal(up.Value, []byte("testpass")) {
			t.Error("User-Password should be encrypted, but matches raw input")
		}

		// Test Fill method
		reply := req.Reply()
		rt2, _ := dict.CreateRequestTemplate(AccessAccept, "Reply-Message")
		rt2.Fill(reply, "Welcome")
		rm := reply.GetAVP(AttrReplyMessage)
		if rm == nil || string(rm.Value) != "Welcome" {
			t.Errorf("Fill failed: got %v", rm)
		}
	})
}
