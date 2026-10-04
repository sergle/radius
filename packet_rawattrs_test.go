package radius

import "testing"

func TestRawAttrs(t *testing.T) {
	type attr struct {
		off   int
		typ   AttributeType
		value string
	}
	tests := []struct {
		name string
		b    []byte
		want []attr
	}{
		{"empty", nil, nil},
		{"well-formed", []byte{1, 4, 'a', 'b', 4, 2, 5, 3, 'c'}, []attr{{0, 1, "ab"}, {4, 4, ""}, {6, 5, "c"}}},
		{"trailing byte", []byte{1, 3, 'a', 9}, []attr{{0, 1, "a"}}},
		{"length past end", []byte{1, 3, 'a', 2, 5, 'b'}, []attr{{0, 1, "a"}}},
		{"length below 2", []byte{1, 3, 'a', 2, 1, 3, 2}, []attr{{0, 1, "a"}}},
		{"zero length", []byte{1, 0, 3, 2}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []attr
			for off, a := range rawAttrs(tc.b) {
				got = append(got, attr{off, a.Type, string(a.Value)})
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestRawAttrsBreak(t *testing.T) {
	b := []byte{1, 3, 'a', 2, 3, 'b', 3, 3, 'c'}
	n := 0
	for _, a := range rawAttrs(b) {
		n++
		if a.Type == 2 {
			break
		}
	}
	if n != 2 {
		t.Fatalf("visited %d attributes, want 2", n)
	}
}
