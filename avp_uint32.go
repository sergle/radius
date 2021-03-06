package radius

import (
	"encoding/binary"
	"strconv"
)

var avpUint32 avpUint32t

type avpUint32t struct{}

func (s avpUint32t) Value(p *Packet, a AVP) interface{} {
	return uint32(binary.BigEndian.Uint32(a.Value))
}

func (s avpUint32t) String(p *Packet, a AVP) string {
	return strconv.Itoa(int(binary.BigEndian.Uint32(a.Value)))
}

func (s avpUint32t) FromString(value string) []byte {
	buf := make([]byte, 4)
	i, _ := strconv.ParseUint(value, 0, 32)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}
