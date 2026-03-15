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
