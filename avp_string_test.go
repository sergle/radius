package radius

import (
	"bytes"
	"testing"
)

func TestAvpString(t *testing.T) {
	handler := avpString

	testCases := []struct {
		name string
		val  string
	}{
		{"Simple", "hello"},
		{"Empty", ""},
		{"WithSpace", "hello world"},
		{"NonASCII", "hëlló"},
		{"LongString", "this is a very long string that should be handled correctly by the radius string avp handler"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test FromString
			bytesVal := handler.FromString(tc.val)
			if !bytes.Equal(bytesVal, []byte(tc.val)) {
				t.Errorf("FromString(%s) = %v; want %v", tc.val, bytesVal, []byte(tc.val))
			}

			// Test Value
			avp := AVP{Value: []byte(tc.val)}
			resVal := handler.Value(nil, avp).(string)
			if resVal != tc.val {
				t.Errorf("Value() = %s; want %s", resVal, tc.val)
			}

			// Test String
			resStr := handler.String(nil, avp)
			if resStr != tc.val {
				t.Errorf("String() = %s; want %s", resStr, tc.val)
			}
		})
	}
}
