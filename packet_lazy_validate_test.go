package radius

import (
	"crypto/md5"
	"errors"
	"testing"
)

// rawPacket builds a packet with attribute bytes attrs; a reply is signed for requestAuth.
func rawPacket(code PacketCode, secret string, requestAuth []byte, attrs []byte) []byte {
	b := rawRequest(code, 1)
	b = append(b, attrs...)
	b[2], b[3] = byte(len(b)>>8), byte(len(b))
	if requestAuth != nil {
		copy(b[4:packetHeaderLen], requestAuth)
		h := md5.New()
		h.Write(b)
		h.Write([]byte(secret))
		copy(b[4:packetHeaderLen], h.Sum(nil))
	}
	return b
}

// ValidateAttributes makes the lazy decoders refuse a malformed attribute list, as DecodeRequest does.
func TestDecodeLazyValidateAttributes(t *testing.T) {
	const secret = "secret"
	requestAuth := make([]byte, authenticatorLen)
	userName := []byte{byte(AttrUserName), 5, 'b', 'o', 'b'}
	eap := []byte{byte(AttrEAPMessage), 6, 2, 1, 0, 4}
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	malformed := map[string][]byte{
		// hides the EAP-Message, so its Message-Authenticator isn't required
		"zero length":    cat(userName, []byte{byte(AttrClass), 0}, eap),
		"length 1":       cat(userName, []byte{byte(AttrClass), 1}, eap),
		"past the end":   cat(userName, []byte{byte(AttrClass), 10, 'x'}),
		"trailing byte":  cat(userName, []byte{byte(AttrClass)}),
		"only one byte":  {byte(AttrClass)},
		"bad then valid": cat([]byte{byte(AttrClass), 0}, userName),
	}
	valid := map[string][]byte{"no attributes": nil, "User-Name": userName}

	strict := &DecodeOptions{ValidateAttributes: true}
	decoders := map[string]func(buf []byte, opts *DecodeOptions) (*Packet, error){
		"DecodeRequestLazy": func(buf []byte, opts *DecodeOptions) (*Packet, error) {
			return DecodeRequestLazyWithOptions(secret, buf, opts)
		},
		"DecodeRequestLazyPooled": func(buf []byte, opts *DecodeOptions) (*Packet, error) {
			return DecodeRequestLazyPooledWithOptions(secret, buf, opts)
		},
		"DecodeReplyLazy": func(buf []byte, opts *DecodeOptions) (*Packet, error) {
			return DecodeReplyLazyWithOptions(secret, buf, requestAuth, opts)
		},
		"DecodeReplyLazyPooled": func(buf []byte, opts *DecodeOptions) (*Packet, error) {
			return DecodeReplyLazyPooledWithOptions(secret, buf, requestAuth, opts)
		},
	}
	for dname, decode := range decoders {
		code, auth := AccessRequest, []byte(nil)
		if dname == "DecodeReplyLazy" || dname == "DecodeReplyLazyPooled" {
			code, auth = AccessAccept, requestAuth
		}
		for name, attrs := range malformed {
			buf := rawPacket(code, secret, auth, attrs)
			if _, err := decode(buf, nil); err != nil {
				t.Errorf("%s %s without the option: %v, want accepted", dname, name, err)
			}
			if _, err := decode(buf, strict); !errors.Is(err, ErrInvalidAttributeLength) {
				t.Errorf("%s %s: err = %v, want ErrInvalidAttributeLength", dname, name, err)
			}
		}
		for name, attrs := range valid {
			p, err := decode(rawPacket(code, secret, auth, attrs), strict)
			if err != nil {
				t.Errorf("%s %s: %v", dname, name, err)
				continue
			}
			if want := string(attrs); string(p.RawAVPs) != want {
				t.Errorf("%s %s: RawAVPs %q, want %q", dname, name, p.RawAVPs, want)
			}
		}
	}

	raw := getLargeRawPacket()
	allocs := testing.AllocsPerRun(100, func() {
		p, err := DecodeRequestLazyPooledWithOptions(secret, raw, strict)
		if err != nil {
			t.Fatal(err)
		}
		p.Release()
	})
	if allocs != 0 {
		t.Errorf("allocs = %v, want 0", allocs)
	}

	// the strict decoders always check, also for a single stray byte
	for name, attrs := range malformed {
		req := rawPacket(AccessRequest, secret, nil, attrs)
		reply := rawPacket(AccessAccept, secret, requestAuth, attrs)
		if _, err := DecodeRequest(secret, req); !errors.Is(err, ErrInvalidAttributeLength) {
			t.Errorf("DecodeRequest %s: err = %v, want ErrInvalidAttributeLength", name, err)
		}
		if _, err := DecodeRequestPooled(secret, req); !errors.Is(err, ErrInvalidAttributeLength) {
			t.Errorf("DecodeRequestPooled %s: err = %v, want ErrInvalidAttributeLength", name, err)
		}
		if _, err := DecodeReply(secret, reply, requestAuth); !errors.Is(err, ErrInvalidAttributeLength) {
			t.Errorf("DecodeReply %s: err = %v, want ErrInvalidAttributeLength", name, err)
		}
	}
}
