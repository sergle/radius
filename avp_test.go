package radius

import (
	"fmt"
	"testing"
)

func TestEnumString(t *testing.T) {
	const unknown = 9999
	tests := []struct {
		known, unk fmt.Stringer
		want       string
	}{
		{AcctStatusTypeEnum(1), AcctStatusTypeEnum(unknown), "Start"},
		{NASPortTypeEnum(1), NASPortTypeEnum(unknown), "Sync"},
		{ServiceTypeEnum(1), ServiceTypeEnum(unknown), "Login"},
		{PromptEnum(1), PromptEnum(unknown), "Echo"},
		{TunnelTypeEnum(1), TunnelTypeEnum(unknown), "PPTP"},
		{TunnelMediumTypeEnum(1), TunnelMediumTypeEnum(unknown), "IPv4"},
		{AcctTerminateCauseEnum(1), AcctTerminateCauseEnum(unknown), "UserRequest"},
	}
	for _, tt := range tests {
		if got := tt.known.String(); got != tt.want {
			t.Errorf("%T(1).String() = %q; want %q", tt.known, got, tt.want)
		}
		if got, want := tt.unk.String(), "unknow code 9999"; got != want {
			t.Errorf("%T(%d).String() = %q; want %q", tt.unk, unknown, got, want)
		}
	}
}

func TestAttributeTypeStringNilDictionary(t *testing.T) {
	old := GetDefaultDictionary()
	SetDefaultDictionary(nil)
	defer SetDefaultDictionary(old)

	if got := AttrUserName.String(); got != "Unknown 1" {
		t.Errorf("String() = %q; want Unknown 1", got)
	}
}
