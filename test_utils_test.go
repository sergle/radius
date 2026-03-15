package radius

import "testing"

func ok(t *testing.T, b bool) {
	if !b {
		t.Helper()
		t.Fatal("fail")
	}
}
