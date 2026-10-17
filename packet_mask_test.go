package radius

import (
	"strings"
	"testing"
)

// StringMasked hides encrypted values that String shows.
func TestStringMasked(t *testing.T) {
	const secret = "testing123"
	d := loadTLVDict(t, encTLVDict+"ATTRIBUTE\tUser-Password\t2\tstring\tencrypt=1\n"+saltTestDict+saltIntDict)
	old := GetDefaultDictionary()
	SetDefaultDictionary(d)
	t.Cleanup(func() { SetDefaultDictionary(old) })

	req := Request(AccessRequest, secret)
	if err := req.AddPassword("pw-user"); err != nil {
		t.Fatal(err)
	}
	if err := addTLV(d, req, "", "Enc-TLV", tlvValue{Name: "Enc-Pass", Value: "pw-tlv"}); err != nil {
		t.Fatal(err)
	}
	reply := req.ReplyAccept()
	if err := reply.AddTunnelPassword(1, "pw-tunnel"); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, reply, "Test", "Test-Secret", "pw-salt"); err != nil {
		t.Fatal(err)
	}
	if err := addTLV(d, reply, "", "Enc-TLV", tlvValue{Name: "Enc-Key", Value: "pw-tlv2"}); err != nil {
		t.Fatal(err)
	}
	if err := addVSA(d, reply, "Alcatel-Lucent-Service-Router", "Alc-LI-Destination", "10.9.8.7"); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"pw-user", "pw-tlv", "pw-tunnel", "pw-salt", "pw-tlv2", "10.9.8.7"}

	var shown, masked string
	for _, p := range []*Packet{req, reply} {
		shown += p.String()
		masked += p.StringMasked()
		for _, a := range p.AVPs {
			shown += a.StringWithPacket(p) + d.DecodeAVPValue(p, a)
			masked += a.StringMasked(p) + a.StringMasked(nil)
		}
	}
	for _, s := range secrets {
		if !strings.Contains(shown, s) {
			t.Errorf("String output misses %q:\n%s", s, shown)
		}
		if strings.Contains(masked, s) {
			t.Errorf("StringMasked output shows %q:\n%s", s, masked)
		}
	}
	if n := strings.Count(req.StringMasked()+reply.StringMasked(), maskedValue); n != len(secrets) {
		t.Errorf("StringMasked output has %d %s, want %d", n, maskedValue, len(secrets))
	}
}
