package radius

import (
	"encoding/binary"
	"strconv"
)

const uint32Size = 4

var avpUint32 AvpUint32

type AvpUint32 struct{}

func (s AvpUint32) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) < uint32Size {
		return uint32(0)
	}
	return uint32(binary.BigEndian.Uint32(a.Value))
}

func (s AvpUint32) String(p *Packet, a AVP) string {
	if len(a.Value) < uint32Size {
		return "invalid"
	}
	return strconv.Itoa(int(binary.BigEndian.Uint32(a.Value)))
}

func (s AvpUint32) FromString(value string) []byte {
	buf := make([]byte, uint32Size)
	i, _ := strconv.ParseUint(value, 0, 32)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}
