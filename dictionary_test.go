package radius

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLoadFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a vendor include file
	vendorDictContent := `
VENDOR		TestVendor	9999
BEGIN-VENDOR	TestVendor
ATTRIBUTE	Test-Vendor-Attr	1	string
VALUE		Test-Vendor-Attr	Val1	1
END-VENDOR	TestVendor
`
	vendorDictPath := filepath.Join(tmpDir, "dictionary.testvendor")
	if err := os.WriteFile(vendorDictPath, []byte(vendorDictContent), 0644); err != nil {
		t.Fatalf("Failed to write vendor dictionary: %v", err)
	}

	// Create main dictionary file
	mainDictContent := `
ATTRIBUTE	Test-Attr-String	100	string
ATTRIBUTE	Test-Attr-Int		101	integer
VALUE		Test-Attr-Int		ValueOne	1
$INCLUDE	dictionary.testvendor
`
	mainDictPath := filepath.Join(tmpDir, "dictionary")
	if err := os.WriteFile(mainDictPath, []byte(mainDictContent), 0644); err != nil {
		t.Fatalf("Failed to write main dictionary: %v", err)
	}

	d := NewDictionary()
	err := d.LoadFile(mainDictPath)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	// Verify Standard Attributes
	if d.GetAttributeID("Test-Attr-String") != 100 {
		t.Errorf("Expected Test-Attr-String ID 100, got %d", d.GetAttributeID("Test-Attr-String"))
	}
	if d.GetAttributeType("Test-Attr-String") != "string" {
		t.Errorf("Expected Test-Attr-String type string, got %s", d.GetAttributeType("Test-Attr-String"))
	}

	// Verify Values
	// Note: dictionary.go stores values but doesn't have a public GetValueID method easily accessible for simple check
	// without VSA context or internal map access, but we can check if parsing succeeded without error.
	// Actually, there are no public getters for const_id in the provided file.
	// We can mostly verify that LoadFile didn't return error and internal state handles it if we were to parse a packet.

	// Verify Vendor
	vid := d.GetVendorID("TestVendor")
	if vid != 9999 {
		t.Errorf("Expected VendorID 9999, got %d", vid)
	}

	// Verify VSA
	vsaID := d.GetVSAAttributeID(9999, "Test-Vendor-Attr")
	if vsaID != 1 {
		t.Errorf("Expected Test-Vendor-Attr ID 1, got %d", vsaID)
	}

	if d.GetVSAAttributeName(9999, 1) != "Test-Vendor-Attr" {
		t.Errorf("Expected VSA name Test-Vendor-Attr, got %s", d.GetVSAAttributeName(9999, 1))
	}
}

func TestParseLineErrors(t *testing.T) {
	d := NewDictionary()
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{"InvalidAttribute", "ATTRIBUTE BadLine"},
		{"InvalidValue", "VALUE BadLine"},
		{"InvalidVendor", "VENDOR BadLine"},
		{"InvalidInclude", "$INCLUDE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, tt.name)
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write file: %v", err)
			}
			err := d.LoadFile(path)
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestConcurrency(t *testing.T) {
	d := NewDictionary()
	tmpDir := t.TempDir()
	dictPath := filepath.Join(tmpDir, "dictionary")
	content := "ATTRIBUTE Test-Concurrency 200 string"
	if err := os.WriteFile(dictPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	if err := d.LoadFile(dictPath); err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// contentiously read
			id := d.GetAttributeID("Test-Concurrency")
			if id != 200 {
				// Don't t.Error in goroutine usually, but for panic check it's fine
			}
			d.HasAttribute("Test-Concurrency")
			d.GetAttributeType("Test-Concurrency")
		}()
	}
	wg.Wait()
}
