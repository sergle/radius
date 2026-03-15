package radius

import (
	"bytes"
	"net"
	"testing"
)

func TestAvpIP(t *testing.T) {
	handler := avpIP

	// Test IPv4
	t.Run("IPv4", func(t *testing.T) {
		ipv4Str := "192.168.1.1"
		ipv4Bytes := []byte{192, 168, 1, 1}

		// Test FromString
		resBytes := handler.FromString(ipv4Str)
		if !bytes.Equal(resBytes, ipv4Bytes) {
			t.Errorf("FromString(%s) = %v; want %v", ipv4Str, resBytes, ipv4Bytes)
		}

		// Test Value
		avp := AVP{Value: ipv4Bytes}
		resVal := handler.Value(nil, avp).(net.IP)
		if !resVal.Equal(net.IP(ipv4Bytes)) {
			t.Errorf("Value() = %v; want %v", resVal, net.IP(ipv4Bytes))
		}

		// Test String
		resStr := handler.String(nil, avp)
		if resStr != ipv4Str {
			t.Errorf("String() = %s; want %s", resStr, ipv4Str)
		}
	})

	// Test IPv6
	t.Run("IPv6", func(t *testing.T) {
		ipv6Str := "2001:db8::1"
		ipv6Bytes := net.ParseIP(ipv6Str)

		// Test FromString
		resBytes := handler.FromString(ipv6Str)
		if !bytes.Equal(resBytes, ipv6Bytes) {
			t.Errorf("FromString(%s) = %v; want %v", ipv6Str, resBytes, ipv6Bytes)
		}

		// Test Value
		avp := AVP{Value: ipv6Bytes}
		resVal := handler.Value(nil, avp).(net.IP)
		if !resVal.Equal(ipv6Bytes) {
			t.Errorf("Value() = %v; want %v", resVal, ipv6Bytes)
		}

		// Test String
		// net.IP.String() might return canonical form
		resStr := handler.String(nil, avp)
		expectedStr := ipv6Bytes.String()
		if resStr != expectedStr {
			t.Errorf("String() = %s; want %s", resStr, expectedStr)
		}
	})

	// Test Invalid IP
	t.Run("Invalid", func(t *testing.T) {
		invalidStr := "not-an-ip"
		resBytes := handler.FromString(invalidStr)
		if resBytes != nil {
			t.Errorf("FromString(%s) expected nil; got %v", invalidStr, resBytes)
		}
	})
}
