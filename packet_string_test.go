package radius

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// slowString formats each AVP on its own, so chainStart scans the packet for it.
func slowString(p *Packet, masked bool) string {
	s := "From: " + p.ClientAddr + "\n" +
		"Code: " + p.Code.String() + "\n" +
		"Identifier: " + strconv.Itoa(int(p.Identifier)) + "\n" +
		"Authenticator: " + fmt.Sprintf("%#v", p.Authenticator) + "\n"
	p.EachAVP(func(a AVP) bool {
		if masked {
			s += a.StringMasked(p) + "\n"
		} else {
			s += a.StringWithPacket(p) + "\n"
		}
		return true
	})
	return s
}

// String marks the same fragments as Continued as formatting each AVP on its own.
func TestPacketStringChains(t *testing.T) {
	useExtDefault(t)
	frag := func(typ AttributeType, ext uint8, more bool, data ...byte) AVP {
		flags := byte(0)
		if more {
			flags = extMoreFlag
		}
		return AVP{Type: typ, Value: append([]byte{ext, flags}, data...)}
	}
	evs := []byte{0, 0, 0x2c, 0x50, 1} // ExtVendor, EV-Anonce
	p := Request(AccessRequest, "secret")
	p.AddAVP(
		frag(245, 1, true, 1), frag(245, 1, true, 2), frag(245, 1, false, 3), // a chain
		frag(245, 1, false, 4),                                                // not continued
		frag(245, 1, true, 5), frag(246, 1, false, 6), frag(245, 1, false, 7), // another type breaks it
		frag(246, 1, true, 8), frag(246, 1, false, 9), // a 246 chain
		frag(245, 1, true, 10), frag(245, 2, true, 11), frag(245, 2, false, 12), // Extended-Type changes
		frag(245, 1, true, 13), AVP{Type: AttrClass, Value: []byte{14}}, frag(245, 1, false, 15), // interrupted
		frag(245, 1, true, 16), AVP{Type: 245, Value: []byte{1}}, frag(245, 1, false, 17), // malformed fragment
		frag(245, ExtTypeEVS, true, append(evs, 18)...), frag(245, ExtTypeEVS, false, 19), // EVS chain
		frag(245, 1, true, 20), frag(245, 1, true, 21), // ends with More
	)
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := DecodeRequestLazy("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*Packet{"built": p, "lazy": lazy} {
		got, want := p.String(), slowString(p, false)
		if got != want {
			t.Errorf("%s: String =\n%s\nwant\n%s", name, got, want)
		}
		if n := strings.Count(got, "Continued"); n != 5 {
			t.Errorf("%s: %d Continued, want 5:\n%s", name, n, got)
		}
		if got, want := p.StringMasked(), slowString(p, true); got != want {
			t.Errorf("%s: StringMasked =\n%s\nwant\n%s", name, got, want)
		}
	}
}

// String of a full-size packet of tiny attributes allocates about its output size,
// not quadratically (v3 #5).
func TestPacketStringAllocs(t *testing.T) {
	for name, p := range stringBenchPackets() {
		out := len(p.String())
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_ = p.String()
		runtime.ReadMemStats(&after)
		if n := after.TotalAlloc - before.TotalAlloc; n > 20*uint64(out) {
			t.Errorf("%s: String allocates %d bytes for %d bytes of output", name, n, out)
		}
	}
}

// String escapes values that would add lines or terminal escapes to a log.
func TestPacketStringEscapes(t *testing.T) {
	const evil = "bob\nCode: AccessAccept\x1b[2J"
	p := Request(AccessRequest, "secret")
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte(evil)})
	p.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte(`"quoted"`)})
	p.AddAVP(AVP{Type: AttrCallingStationId, Value: []byte("a\u202eb")})
	p.AddAVP(AVP{Type: AttrTunnelPrivateGroupID, Value: []byte("\x01vlan\r10")})
	p.AddAVP(AVP{Type: AttrNASIdentifier, Value: []byte("nas 1, ok")})
	if err := p.AddPassword("pw\n"); err != nil {
		t.Fatal(err)
	}
	s := p.String()
	for _, want := range []string{
		`AVP type: User-Name "bob\nCode: AccessAccept\x1b[2J"`,
		`AVP type: Reply-Message "\"quoted\""`,
		`AVP type: Calling-Station-Id "a\u202eb"`,
		`AVP type: Tunnel-Private-Group-ID "vlan\r10" (tag 1)`,
		`AVP type: NAS-Identifier nas 1, ok`,
		`AVP type: User-Password "pw\n"`,
	} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	if strings.Count(s, "\n") != 4+6 || strings.ContainsRune(s, '\x1b') {
		t.Errorf("unescaped output:\n%s", s)
	}

	r := p.Reply()
	if err := r.AddTunnelPassword(1, "tp\x00\x07"); err != nil {
		t.Fatal(err)
	}
	if s, want := r.String(), `AVP type: Tunnel-Password "tp\x00\a" (tag 1)`; !strings.Contains(s, want+"\n") {
		t.Errorf("missing %s in\n%s", want, s)
	}
	if s, want := r.StringMasked(), `AVP type: Tunnel-Password ***** (tag 1)`; !strings.Contains(s, want+"\n") {
		t.Errorf("missing %s in\n%s", want, s)
	}
}
