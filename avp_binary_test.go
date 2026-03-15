package radius

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAvpBinary(t *testing.T) {
	handler := avpBinary

	t.Run("Value", func(t *testing.T) {
		input := []byte{0xde, 0xad, 0xbe, 0xef}
		avp := AVP{Value: input}
		res := handler.Value(nil, avp).([]byte)
		if !bytes.Equal(res, input) {
			t.Errorf("Value() = %v; want %v", res, input)
		}
	})

	t.Run("String", func(t *testing.T) {
		input := []byte{0x01, 0x02}
		avp := AVP{Value: input}
		res := handler.String(nil, avp)
		expected := fmt.Sprintf("%#v", input)
		if res != expected {
			t.Errorf("String() = %s; want %s", res, expected)
		}
	})

	t.Run("FromString", func(t *testing.T) {
		input := "raw data"
		res := handler.FromString(input)
		expected := []byte(input)
		if !bytes.Equal(res, expected) {
			t.Errorf("FromString(%s) = %v; want %v", input, res, expected)
		}
	})

	t.Run("Empty", func(t *testing.T) {
		input := []byte{}
		avp := AVP{Value: input}
		if !bytes.Equal(handler.Value(nil, avp).([]byte), input) {
			t.Errorf("Value() failed for empty input")
		}
		if handler.String(nil, avp) != "[]byte{}" {
			t.Errorf("String() = %s; want []byte{}", handler.String(nil, avp))
		}
	})
}
