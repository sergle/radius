package radius

import (
	"bytes"
	"testing"
)

func TestTemplate(t *testing.T) {
	dict := NewDictionary()
	// Mock some attributes so we don't depend on external file for unit test
	dict.attr_id["User-Name"] = AttrUserName
	dict.attr_type["User-Name"] = "string"
	dict.attr_id["User-Password"] = AttrUserPassword
	dict.attr_type["User-Password"] = "string"
	dict.attr_id["NAS-IP-Address"] = AttrNASIPAddress
	dict.attr_type["NAS-IP-Address"] = "ipaddr"
	dict.attr_id["Reply-Message"] = AttrReplyMessage
	dict.attr_type["Reply-Message"] = "string"

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
