package radius

import (
	"testing"
)

func getLargeRawPacket() []byte {
	// Header: Code (1), ID (1), Length (2), Authenticator (16)
	raw := []byte{
		0x01, 0x01, 0x01, 0x1c, // Code: Access-Request, ID: 1, Length: 284 (20 + 20*13 + 4 safety)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // Authenticator
	}
	// Add 20 attributes of type 1 (User-Name) with length 13
	for i := 0; i < 20; i++ {
		raw = append(raw, 0x01, 0x0d, 'b', 'e', 'n', 'c', 'h', 'm', 'a', 'r', 'k', '-', byte('a'+i))
	}
	// Total length: 20 + 20*13 = 280.
	// Update length in header
	raw[2] = 0x01
	raw[3] = 0x18 // 280 in hex
	return raw
}

func BenchmarkDecodePacketLarge(b *testing.B) {
	rawPacket := getLargeRawPacket()
	secret := "secret"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecodeRequest(secret, rawPacket)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodePacketLazyLarge(b *testing.B) {
	rawPacket := getLargeRawPacket()
	secret := "secret"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecodeRequestLazy(secret, rawPacket)
		if err != nil {
			b.Fatal(err)
		}
	}
}
