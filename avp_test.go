package radius

import (
	"testing"
)

func TestAvpUint32Enum(t *testing.T) {
	enum := AvpUint32Enum{AcctStatusTypeEnum(0)}
	s := enum.String(nil, AVP{
		Value: []byte{0, 0, 0, 1},
	})
	if s != "Start" {
		t.Errorf("Expected Start, got %s", s)
	}
	v1 := enum.Value(nil, AVP{
		Value: []byte{0, 0, 0, 1},
	}).(AcctStatusTypeEnum)
	if v1 != AcctStatusTypeEnumStart {
		t.Errorf("Expected %v, got %v", AcctStatusTypeEnumStart, v1)
	}
}
