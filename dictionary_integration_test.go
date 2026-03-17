package radius

import (
	"testing"
)

func TestDictionaryIntegration(t *testing.T) {
	dict := NewDictionary()
	// Mock a custom attribute
	// Custom attributes are typically > 100 or specific to an implementation
	customAttrID := AttributeType(199)
	dict.attrID["Custom-Attribute"] = customAttrID
	dict.attrName[customAttrID] = "Custom-Attribute"
	dict.attrType["Custom-Attribute"] = "string"

	old := GetDefaultDictionary()
	SetDefaultDictionary(dict)
	defer SetDefaultDictionary(old)

	avp := AVP{
		Type:  customAttrID,
		Value: []byte("custom value"),
	}

	decoded := avp.Decode(nil)
	if decoded.(string) != "custom value" {
		t.Errorf("Expected 'custom value', got %v", decoded)
	}

	if avp.Type.String() != "Custom-Attribute" {
		t.Errorf("Expected 'Custom-Attribute', got %v", avp.Type.String())
	}
}
