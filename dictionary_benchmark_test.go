package radius

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func generateBenchmarkDictionary(b *testing.B, dir string, numAttributes int) string {
	content := ""
	for i := 0; i < numAttributes; i++ {
		// Recycle IDs to avoid parsing errors (dictionary.go enforces 8-bit IDs)
		id := i%255 + 1
		content += fmt.Sprintf("ATTRIBUTE Attr-%d %d string\n", i, id)
		content += fmt.Sprintf("VALUE Attr-%d Val-%d %d\n", i, i, i)
	}

	path := filepath.Join(dir, "dictionary.bench")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		b.Fatalf("Failed to write benchmark dictionary: %v", err)
	}
	return path
}

func BenchmarkLoadFile(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	tmpDir := b.TempDir()
	path := generateBenchmarkDictionary(b, tmpDir, 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := NewDictionary()
		if err := d.LoadFile(path); err != nil {
			b.Fatalf("LoadFile failed: %v", err)
		}
	}
}

var benchNASPortAVP = AVP{Type: AttrNASPort, Value: []byte{0, 0, 0, 7}}

func BenchmarkAVPDecode(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = benchNASPortAVP.Decode(nil)
	}
}

func BenchmarkAVPDecodeParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = benchNASPortAVP.Decode(nil)
		}
	})
}

func BenchmarkAVPString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = benchNASPortAVP.String()
	}
}

func BenchmarkAttributeTypeString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AttrNASPort.String()
	}
}

func BenchmarkDecodeAVPValue(b *testing.B) {
	d := GetDefaultDictionary()
	a := AVP{Type: AttrServiceType, Value: []byte{0, 0, 0, 2}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.DecodeAVPValue(nil, a)
	}
}

func BenchmarkEnumString(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AcctStatusTypeEnumInterimUpdate.String()
	}
}

func BenchmarkAvpUint32EnumString(b *testing.B) {
	enum := AvpUint32Enum{AcctStatusTypeEnum(0)}
	a := AVP{Type: AttrAcctStatusType, Value: []byte{0, 0, 0, 3}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = enum.String(nil, a)
	}
}

func BenchmarkAvpUint32EnumValue(b *testing.B) {
	enum := AvpUint32Enum{AcctStatusTypeEnum(0)}
	a := AVP{Type: AttrAcctStatusType, Value: []byte{0, 0, 0, 3}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = enum.Value(nil, a)
	}
}
