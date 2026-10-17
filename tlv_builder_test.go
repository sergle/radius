package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// AddTLV starts a new nested instance; Add reuses the last one.
func TestTLVBuilderNested(t *testing.T) {
	d := loadTLVTestDict(t)
	b, err := d.ParseTLV("TLVVendor", "TLV-Remote")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Add("TLV-Remote-Nested-Name", "a"); err != nil {
		t.Fatal(err)
	}
	n, err := b.AddTLV("TLV-Remote-Nested")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Add("TLV-Remote-Nested-Name", "b"); err != nil {
		t.Fatal(err)
	}
	for _, v := range [][2]string{{"TLV-Remote-Nested-Count", "7"}, {"TLV-Remote-Mask", "9"}} {
		if err := b.Add(v[0], v[1]); err != nil {
			t.Fatal(err)
		}
	}
	want := vsaAVP(testTLVVendorID, 2, []byte{4, 5, 1, 3, 'a', 4, 8, 1, 3, 'b', 2, 3, 7, 2, 6, 0, 0, 0, 9})
	if avp := b.ToAVP(); !bytes.Equal(avp.Value, want.Value) {
		t.Errorf("ToAVP = %v, want %v", avp.Value, want.Value)
	}

	if err := n.Add("TLV-Remote-Addr", "10.0.0.1"); !errors.Is(err, ErrUnknownAttribute) {
		t.Errorf("Add outside the nested TLV: err = %v", err)
	}
	if err := b.Add("TLV-Remote-Nested", "1"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("Add nested TLV with a value: err = %v", err)
	}
	if _, err := b.AddTLV("TLV-Remote-Addr"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("AddTLV non-TLV: err = %v", err)
	}
	p := Request(AccessRequest, "secret")
	if err := p.AddTLV(n); !errors.Is(err, ErrInvalidValue) || len(p.AVPs) != 0 {
		t.Errorf("Packet.AddTLV nested: err = %v, AVPs %v", err, p.AVPs)
	}
	// a nested TLV holds one or more sub-attributes (RFC 6929)
	if _, err := b.AddTLV("TLV-Remote-Nested"); err != nil {
		t.Fatal(err)
	}
	if err := p.AddTLV(b); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("empty nested instance: err = %v", err)
	}
	if err := p.AddTLV(nil); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("Packet.AddTLV(nil): err = %v", err)
	}
}

// Add checks values before any packet is involved.
func TestTLVBuilderAddErrors(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	b, err := d.ParseTLV("", "Enc-TLV")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, value string
		want        error
	}{
		{"Enc-Secret", "x", ErrUnsupportedAttributeType},
		{"Enc-Pass", strings.Repeat("p", maxPasswordLen+1), ErrInvalidValue},
		{"Enc-Key", strings.Repeat("k", tunnelPasswordMaxLen+1), ErrInvalidValue},
		{"Enc-Int", "x", ErrInvalidValue},
		{"Enc-TLV", "x", ErrUnknownAttribute},
		{"Tunnel-Password", "x", ErrUnknownAttribute},
	}
	for _, c := range cases {
		if err := b.Add(c.name, c.value); !errors.Is(err, c.want) {
			t.Errorf("Add %s (%d bytes): err = %v, want %v", c.name, len(c.value), err, c.want)
		}
	}
	if _, err := d.ParseTLV("", "Enc-Pass"); !errors.Is(err, ErrUnknownAttribute) {
		t.Errorf("ParseTLV sub-attribute: err = %v", err)
	}
	if _, err := d.ParseTLV("", "Tunnel-Password"); !errors.Is(err, ErrUnsupportedAttributeType) {
		t.Errorf("ParseTLV non-TLV: err = %v", err)
	}
}

// Packet.AddTLV encrypts with each packet and leaves the TLV as it was; ToAVP refuses to encrypt.
func TestTLVBuilderSeveralPackets(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	b, err := d.ParseTLV("", "Enc-TLV")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range [][2]string{{"Enc-Pass", "hunter2"}, {"Enc-Key", "tunnel-pass"}, {"Enc-Num", "5"}} {
		if err := b.Add(v[0], v[1]); err != nil {
			t.Fatal(err)
		}
	}
	if avp := b.ToAVP(); avp.Type != 0 || avp.Value != nil {
		t.Errorf("ToAVP with encrypted values = %v, want zero AVP", avp)
	}
	var values [][]byte
	for range 2 {
		reply := Request(AccessRequest, encTLVSecret).ReplyAccept()
		if err := reply.AddTLV(b); err != nil {
			t.Fatal(err)
		}
		values = append(values, reply.AVPs[0].Value)
		for _, w := range [][2]string{{"Enc-Pass", "hunter2"}, {"Enc-Key", "tunnel-pass"}} {
			if got, ok := d.GetTLV(reply, "", w[0]); !ok || string(got) != w[1] {
				t.Errorf("GetTLV %s = %q, %v", w[0], got, ok)
			}
		}
	}
	if bytes.Equal(values[0], values[1]) {
		t.Error("same ciphertext for two requests")
	}
}

// Packet.AddTLV splits values too long for one AVP where the format allows it; ToAVP doesn't.
func TestTLVBuilderSplit(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	long := strings.Repeat("x", 200)
	cases := []struct {
		vendor, attr, name string
	}{
		{"WiMAX", "WiMAX-hDHCP-Server-Parameters", "WiMAX-hDHCP-DHCP-RK"},
		{"", "Long-Enc", "Long-Enc-Key"},
		{"", "Long-Enc", "Long-Enc-Blob"},
	}
	for _, c := range cases {
		b, err := d.ParseTLV(c.vendor, c.attr)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Add(c.name, long); err != nil {
			t.Fatal(err)
		}
		if err := b.Add(c.name, long[:100]); err != nil {
			t.Fatal(err)
		}
		reply := Request(AccessRequest, encTLVSecret).ReplyAccept()
		if err := reply.AddTLV(b); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(reply.AVPs) != 2 {
			t.Errorf("%s: %d AVPs, want 2", c.name, len(reply.AVPs))
		}
		if got, ok := d.GetTLV(reply, c.vendor, c.name); !ok || string(got) != long {
			t.Errorf("%s: GetTLV = %q, %v", c.name, got, ok)
		}
		if avp := b.ToAVP(); avp.Value != nil {
			t.Errorf("%s: ToAVP of a long value = %v, want zero AVP", c.name, avp)
		}
	}

	// formats without continuation can't split
	b, err := d.ParseTLV("", "Enc-TLV")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := b.Add("Enc-Key", long[:150]); err != nil {
			t.Fatal(err)
		}
	}
	reply := Request(AccessRequest, encTLVSecret).ReplyAccept()
	if err := reply.AddTLV(b); !errors.Is(err, ErrInvalidValue) || len(reply.AVPs) != 0 || len(reply.salts) != 0 {
		t.Errorf("too long: err = %v, AVPs %v, salts %v", err, reply.AVPs, reply.salts)
	}
}
