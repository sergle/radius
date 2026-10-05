package radius

import "testing"

func TestAttributeTypeStringNilDictionary(t *testing.T) {
	old := GetDefaultDictionary()
	SetDefaultDictionary(nil)
	defer SetDefaultDictionary(old)

	if got := AttrUserName.String(); got != "Unknown 1" {
		t.Errorf("String() = %q; want Unknown 1", got)
	}
}
