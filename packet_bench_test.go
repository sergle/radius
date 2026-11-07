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
	for i := range 20 {
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

func BenchmarkDecodePacketPooledLarge(b *testing.B) {
	rawPacket := getLargeRawPacket()
	secret := "secret"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := DecodeRequestPooled(secret, rawPacket)
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
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

func BenchmarkDecodePacketLazyPooledLarge(b *testing.B) {
	rawPacket := getLargeRawPacket()
	secret := "secret"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := DecodeRequestLazyPooled(secret, rawPacket)
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
	}
}

func BenchmarkDecodePacketLazyPooledValidateLarge(b *testing.B) {
	raw := getLargeRawPacket()
	opts := &DecodeOptions{ValidateAttributes: true}
	b.ReportAllocs()
	for b.Loop() {
		p, err := DecodeRequestLazyPooledWithOptions("secret", raw, opts)
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
	}
}

func BenchmarkEncodePacket(b *testing.B) {
	p := Request(AccessRequest, "secret")
	for range 20 {
		p.AddAVP(AVP{Type: 1, Value: []byte("benchmark-x")})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.Encode()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodePacketTo(b *testing.B) {
	p := Request(AccessRequest, "secret")
	for range 20 {
		p.AddAVP(AVP{Type: 1, Value: []byte("benchmark-x")})
	}
	buf := make([]byte, maxPacketLen)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.EncodeTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLazyAccessors(b *testing.B) {
	p, err := DecodeRequestLazy("secret", getLargeRawPacket())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p.HasAVP(AttrNASIPAddress) || p.GetAVP(AttrNASIPAddress) != nil {
			b.Fatal("unexpected attribute")
		}
		n := 0
		p.EachAVP(func(AVP) bool { n++; return true })
		if n != 20 {
			b.Fatal(n)
		}
	}
}

// stringBenchPackets are full-size packets of many small attributes (v3 #5).
func stringBenchPackets() map[string]*Packet {
	small := Request(AccessRequest, "secret")
	small.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	small.AddAVP(AVP{Type: AttrNASIPAddress, Value: []byte{10, 0, 0, 1}})
	small.AddAVP(AVP{Type: AttrNASPort, Value: []byte{0, 0, 0, 7}})
	small.AddAVP(AVP{Type: AttrCallingStationId, Value: []byte("00-11-22-33-44-55")})

	empty := Request(AccessRequest, "secret")
	for range (maxPacketLen - packetHeaderLen) / 2 {
		empty.AddAVP(AVP{Type: AttrClass})
	}

	// one long-extended chain of 1-byte fragments
	long := Request(AccessRequest, "secret")
	const n = (maxPacketLen - packetHeaderLen) / 5
	for i := range n {
		flags := byte(extMoreFlag)
		if i == n-1 {
			flags = 0
		}
		long.AddAVP(AVP{Type: 245, Value: []byte{1, flags, byte(i)}})
	}
	return map[string]*Packet{"Small": small, "Empty2038": empty, "LongExt815": long}
}

func BenchmarkPacketString(b *testing.B) {
	for name, p := range stringBenchPackets() {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = p.String()
			}
		})
		b.Run(name+"Masked", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = p.StringMasked()
			}
		})
	}
}
