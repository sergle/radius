package radius

import (
	"bytes"
	"testing"
)

func TestAvpUint32(t *testing.T) {
	handler := avpUint32

	testCases := []struct {
		name     string
		strVal   string
		bytesVal []byte
		uintVal  uint32
	}{
		{"Zero", "0", []byte{0, 0, 0, 0}, 0},
		{"One", "1", []byte{0, 0, 0, 1}, 1},
		{"Max", "4294967295", []byte{255, 255, 255, 255}, 4294967295},
		{"Arbitrary", "123456789", []byte{7, 91, 205, 21}, 123456789},
		{"Hex", "0x12345678", []byte{0x12, 0x34, 0x56, 0x78}, 0x12345678},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test FromString
			resBytes := handler.FromString(tc.strVal)
			if !bytes.Equal(resBytes, tc.bytesVal) {
				t.Errorf("FromString(%s) = %v; want %v", tc.strVal, resBytes, tc.bytesVal)
			}

			// Test Value
			avp := AVP{Value: tc.bytesVal}
			resVal := handler.Value(nil, avp).(uint32)
			if resVal != tc.uintVal {
				t.Errorf("Value() = %d; want %d", resVal, tc.uintVal)
			}

			// Test String
			// handler.String returns base-10 string (uses strconv.Itoa)
			resStr := handler.String(nil, avp)
			expectedStr := tc.strVal
			if tc.name == "Hex" {
				expectedStr = "305419896" // 0x12345678 in decimal
			}
			if resStr != expectedStr {
				t.Errorf("String() = %s; want %s", resStr, expectedStr)
			}
		})
	}
}
