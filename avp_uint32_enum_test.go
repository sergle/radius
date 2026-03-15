package radius

import (
	"bytes"
	"testing"
)

type dummyEnum uint32

func (e dummyEnum) String() string {
	if e == 1 {
		return "One"
	}
	return "Unknown"
}

func TestAvpUint32EnumDetailed(t *testing.T) {
	// 1. Test with a type that has String() method (AcctStatusTypeEnum)
	t.Run("StatusEnum", func(t *testing.T) {
		handler := AvpUint32Enum{AcctStatusTypeEnum(0)}
		avp := AVP{Value: []byte{0, 0, 0, 1}} // Start

		// Test Value()
		val := handler.Value(nil, avp).(AcctStatusTypeEnum)
		if val != AcctStatusTypeEnumStart {
			t.Errorf("Value() = %v; want %v", val, AcctStatusTypeEnumStart)
		}

		// Test String()
		str := handler.String(nil, avp)
		if str != "Start" {
			t.Errorf("String() = %s; want Start", str)
		}
	})

	// 2. Test with custom enum type
	t.Run("CustomEnum", func(t *testing.T) {
		handler := AvpUint32Enum{dummyEnum(0)}

		// Known value
		avp1 := AVP{Value: []byte{0, 0, 0, 1}}
		if handler.String(nil, avp1) != "One" {
			t.Errorf("String(1) = %s; want One", handler.String(nil, avp1))
		}

		// Unknown value
		avp2 := AVP{Value: []byte{0, 0, 0, 2}}
		if handler.String(nil, avp2) != "Unknown" {
			t.Errorf("String(2) = %s; want Unknown", handler.String(nil, avp2))
		}
	})

	// 3. Test with raw uint32 type (no String method)
	t.Run("RawUint32", func(t *testing.T) {
		handler := AvpUint32Enum{uint32(0)}
		avp := AVP{Value: []byte{0, 0, 0, 123}}

		// Test Value()
		val := handler.Value(nil, avp).(uint32)
		if val != 123 {
			t.Errorf("Value() = %v; want 123", val)
		}

		// Test String() - should fallback to numeric string
		str := handler.String(nil, avp)
		if str != "123" {
			t.Errorf("String() = %s; want 123", str)
		}
	})

	// 4. Test FromString stub
	t.Run("FromStringStub", func(t *testing.T) {
		handler := AvpUint32Enum{uint32(0)}
		input := "123"
		res := handler.FromString(input)
		// Current implementation just returns []byte(input)
		if !bytes.Equal(res, []byte(input)) {
			t.Errorf("FromString(%s) = %v; want %v", input, res, []byte(input))
		}
	})
}
