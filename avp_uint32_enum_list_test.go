package radius

import (
	"bytes"
	"testing"
)

func TestAvpUint32EnumList(t *testing.T) {
	enumList := AvpUint32EnumList{"Zero", "One", "Two"}

	t.Run("Value", func(t *testing.T) {
		avp := AVP{Value: []byte{0, 0, 0, 1}}
		val := enumList.Value(nil, avp).(uint32)
		if val != 1 {
			t.Errorf("Value() = %d; want 1", val)
		}
	})

	t.Run("StringInRange", func(t *testing.T) {
		avp := AVP{Value: []byte{0, 0, 0, 1}}
		str := enumList.String(nil, avp)
		if str != "One" {
			t.Errorf("String() = %s; want One", str)
		}
	})

	t.Run("StringOutOfRange", func(t *testing.T) {
		avp := AVP{Value: []byte{0, 0, 0, 5}}
		str := enumList.String(nil, avp)
		if str != "unknow 5" {
			t.Errorf("String() = %s; want unknow 5", str)
		}
	})

	t.Run("StringEmptyEntry", func(t *testing.T) {
		extendedList := AvpUint32EnumList{"Zero", "", "Two"}
		avp := AVP{Value: []byte{0, 0, 0, 1}}
		str := extendedList.String(nil, avp)
		if str != "unknow 1" {
			t.Errorf("String() = %s; want unknow 1", str)
		}
	})

	t.Run("FromString", func(t *testing.T) {
		input := "One"
		res := enumList.FromString(input)
		if !bytes.Equal(res, []byte(input)) {
			t.Errorf("FromString(%s) = %v; want %v", input, res, []byte(input))
		}
	})
}
