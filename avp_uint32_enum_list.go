package radius

import (
	"encoding/binary"
	"strconv"
)

// not used?
type AvpUint32EnumList []string

func (s AvpUint32EnumList) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) < 4 {
		return uint32(0)
	}
	return uint32(binary.BigEndian.Uint32(a.Value))
}
func (s AvpUint32EnumList) String(p *Packet, a AVP) string {
	if len(a.Value) < 4 {
		return "invalid"
	}
	number := int(binary.BigEndian.Uint32(a.Value))
	if number > len(s) {
		return "unknow " + strconv.Itoa(number)
	}
	out := s[number]
	if out == "" {
		return "unknow " + strconv.Itoa(number)
	}
	return out
}

func (s AvpUint32EnumList) FromString(v string) []byte {
	return []byte(v)
}
