package radius

import (
	"encoding/binary"
	"strconv"
	"strings"
)

const (
	tagMax       = 0x1F // RFC 2868: a larger first byte of a tagged string belongs to the string
	taggedIntMax = 1<<24 - 1
)

var (
	avpTaggedUint32 AvpTaggedUint32
	avpTaggedString AvpTaggedString
)

// AvpTaggedUint32 handles RFC 2868 tagged integers: a 1-byte tag and a 24-bit value.
type AvpTaggedUint32 struct{}

func (s AvpTaggedUint32) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) < uint32Size {
		return uint32(0)
	}
	return binary.BigEndian.Uint32(a.Value) & taggedIntMax
}

func (s AvpTaggedUint32) String(p *Packet, a AVP) string {
	if len(a.Value) < uint32Size {
		return "invalid"
	}
	return withTag(strconv.Itoa(int(s.Value(p, a).(uint32))), a.Value[0])
}

func (s AvpTaggedUint32) FromString(v string) []byte {
	buf, _ := parseUint32(v)
	buf[0] = 0
	return buf
}

// AvpTaggedString handles RFC 2868 tagged strings, where the tag byte is optional.
type AvpTaggedString struct{}

func (s AvpTaggedString) Value(p *Packet, a AVP) interface{} {
	_, v := splitTaggedString(a.Value)
	return string(v)
}

func (s AvpTaggedString) String(p *Packet, a AVP) string {
	tag, v := splitTaggedString(a.Value)
	return withTag(printable(string(v)), tag)
}

func (s AvpTaggedString) FromString(v string) []byte {
	return encodeTaggedString(0, v)
}

func splitTaggedString(v []byte) (uint8, []byte) {
	if len(v) > 0 && v[0] <= tagMax {
		return v[0], v[1:]
	}
	return 0, v
}

// encodeTaggedString omits a zero tag unless the string itself starts like a tag.
func encodeTaggedString(tag uint8, s string) []byte {
	if tag == 0 && (s == "" || s[0] > tagMax) {
		return []byte(s)
	}
	return append([]byte{tag}, s...)
}

func withTag(s string, tag uint8) string {
	if tag == 0 {
		return s
	}
	return s + " (tag " + strconv.Itoa(int(tag)) + ")"
}

// splitTagName splits a FreeRADIUS-style "Name:tag" attribute name.
func splitTagName(name string) (base string, tag uint8, tagged bool, err error) {
	i := strings.LastIndexByte(name, ':')
	if i < 0 {
		return name, 0, false, nil
	}
	n, err := strconv.ParseUint(name[i+1:], 10, 8)
	if err != nil || n > tagMax {
		return "", 0, false, ErrInvalidTag
	}
	return name[:i], uint8(n), true, nil
}

func isTagged(handler avpDataType) bool {
	return handler == avpTaggedUint32 || handler == avpTaggedString || handler == avpTunnelPassword
}
