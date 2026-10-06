package radius

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// ifid value: an 8-byte IPv6 interface identifier written as four 16-bit hex groups.
const (
	ifidLen       = 8
	ifidGroups    = 4
	ifidGroupLen  = 2
	ifidMaxDigits = 4
)

var avpIfid AvpIfid

// AvpIfid handles "ifid" attributes (RFC 3162), e.g. Framed-Interface-Id; Value returns the raw bytes.
type AvpIfid struct{}

func (s AvpIfid) Value(p *Packet, a AVP) interface{} {
	return a.Value
}

// String formats the value as FreeRADIUS does, e.g. "11:2233:abc:0".
func (s AvpIfid) String(p *Packet, a AVP) string {
	if len(a.Value) != ifidLen {
		return avpBinary.String(p, a)
	}
	groups := make([]string, ifidGroups)
	for i := range groups {
		groups[i] = strconv.FormatUint(uint64(binary.BigEndian.Uint16(a.Value[i*ifidGroupLen:])), 16)
	}
	return strings.Join(groups, ":")
}

// FromString parses four colon-separated groups of 1-4 hex digits, or returns nil.
func (s AvpIfid) FromString(v string) []byte {
	groups := strings.Split(v, ":")
	if len(groups) != ifidGroups {
		return nil
	}
	b := make([]byte, 0, ifidLen)
	for _, g := range groups {
		if len(g) == 0 || len(g) > ifidMaxDigits {
			return nil
		}
		n, err := strconv.ParseUint(g, 16, 16)
		if err != nil {
			return nil
		}
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	return b
}
