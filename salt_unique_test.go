package radius

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// cycleReader returns the bytes of b over and over.
type cycleReader struct {
	b []byte
	i int
}

func (r *cycleReader) Read(p []byte) (int, error) {
	for n := range p {
		p[n] = r.b[r.i%len(r.b)]
		r.i++
	}
	return len(p), nil
}

// setSaltRand makes salts come from b for the rest of the test.
func setSaltRand(t *testing.T, b ...byte) {
	t.Helper()
	old := saltRand
	saltRand = &cycleReader{b: b}
	t.Cleanup(func() { saltRand = old })
}

// Every encrypt=2 path gives a salt unique within the packet (RFC 2868 section 3.5, RFC 2548 section 2.4.2).
func TestSaltsUniqueInPacket(t *testing.T) {
	salts := loadSaltDict(t)
	tlvs := loadTLVDict(t, encTLVDict)
	tunnelTmpl, err := tlvs.GetTemplate("Tunnel-Password:1")
	if err != nil {
		t.Fatal(err)
	}
	vsaTmpl, err := salts.getVSATemplate("Microsoft", "MS-MPPE-Send-Key")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		add  func(p *Packet) error
		salt func(a AVP) []byte
	}{
		{"AddTunnelPassword", func(p *Packet) error { return p.AddTunnelPassword(1, "pw") },
			func(a AVP) []byte { return a.Value[tunnelTagLen:tunnelHeaderLen] }},
		{"AddVSA", func(p *Packet) error { return addVSA(salts, p, "Microsoft", "MS-MPPE-Send-Key", "key") },
			func(a AVP) []byte { return ToVSA(a).Value[:tunnelSaltLen] }},
		{"AddVSA tagged", func(p *Packet) error { return addVSA(salts, p, "Test", "Test-Tunnel:3", "pw") },
			func(a AVP) []byte { return ToVSA(a).Value[tunnelTagLen:tunnelHeaderLen] }},
		{"AddTLV", func(p *Packet) error { return addTLV(tlvs, p, "", "Enc-TLV", tlvValue{Name: "Enc-Key", Value: "key"}) },
			func(a AVP) []byte { return a.Value[tlvHeaderLen : tlvHeaderLen+tunnelSaltLen] }},
		{"template", func(p *Packet) error { tunnelTmpl.Add(p, "pw"); return nil },
			func(a AVP) []byte { return a.Value[tunnelTagLen:tunnelHeaderLen] }},
		{"VSA template", func(p *Packet) error { vsaTmpl.Add(p, "key"); return nil },
			func(a AVP) []byte { return ToVSA(a).Value[:tunnelSaltLen] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// the same salt twice, then another
			setSaltRand(t, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04)
			p := Request(AccessRequest, "testing123").ReplyAccept()
			for range 2 {
				if err := tc.add(p); err != nil {
					t.Fatal(err)
				}
			}
			if len(p.AVPs) != 2 {
				t.Fatalf("got %d AVPs, want 2", len(p.AVPs))
			}
			s0, s1 := tc.salt(p.AVPs[0]), tc.salt(p.AVPs[1])
			if bytes.Equal(s0, s1) {
				t.Errorf("both salts are %x", s0)
			}
			if s0[0]&tunnelSaltBit == 0 || s1[0]&tunnelSaltBit == 0 {
				t.Errorf("salts %x, %x lack the high bit", s0, s1)
			}
		})
	}
}

// Salts are unique across paths, start afresh in a reset packet, and survive Copy.
func TestSaltsUniqueAcrossPaths(t *testing.T) {
	d := loadSaltDict(t)
	setSaltRand(t, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04)
	p := Request(AccessRequest, "testing123").ReplyAccept()
	if err := p.AddTunnelPassword(1, "pw"); err != nil {
		t.Fatal(err)
	}
	c := p.Copy()
	if err := addVSA(d, c, "Microsoft", "MS-MPPE-Send-Key", "key"); err != nil {
		t.Fatal(err)
	}
	if s0, s1 := c.AVPs[0].Value[tunnelTagLen:tunnelHeaderLen], ToVSA(c.AVPs[1]).Value[:tunnelSaltLen]; bytes.Equal(s0, s1) {
		t.Errorf("both salts are %x", s0)
	}

	setSaltRand(t, 0x01, 0x02)
	auth := p.Authenticator
	p.Reset()
	p.Code, p.Secret, p.Authenticator = AccessAccept, "testing123", auth
	// would loop forever if the earlier salt were still taken
	if err := p.AddTunnelPassword(1, "pw"); err != nil {
		t.Fatal(err)
	}
}

// A packet with every salt taken refuses another value instead of looping.
func TestSaltsExhausted(t *testing.T) {
	p := Request(AccessRequest, "testing123").ReplyAccept()
	for i := range maxSalts {
		p.salts = append(p.salts, uint16(i)|tunnelSaltBit<<8)
	}
	if err := p.AddTunnelPassword(1, "pw"); !errors.Is(err, ErrInvalidPacketLength) {
		t.Errorf("AddTunnelPassword error = %v, want ErrInvalidPacketLength", err)
	}
}

// A failed AddTLV gives back the salts of its earlier values.
func TestSaltsRestoredOnError(t *testing.T) {
	d := loadTLVDict(t, encTLVDict)
	p := Request(AccessRequest, "testing123").ReplyAccept()
	// too long only once encrypted
	key := tlvValue{Name: "Enc-Key", Value: strings.Repeat("k", 120)}
	if err := addTLV(d, p, "", "Enc-TLV", key, key); err == nil {
		t.Fatal("AddTLV accepted a value too long")
	}
	if len(p.salts) != 0 || len(p.AVPs) != 0 {
		t.Errorf("packet changed: salts %x, AVPs %v", p.salts, p.AVPs)
	}
}
