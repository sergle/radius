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
	buf, _ := parseUint32(value)
	return buf
}

// parseUint32 encodes a number (decimal, or 0x/0o/0b prefixed) as 4 bytes big-endian.
func parseUint32(value string) ([]byte, error) {
	i, err := strconv.ParseUint(value, 0, 32)
	return encodeUint32(uint32(i)), err
}

// encodeUint32 returns v as 4 bytes big-endian.
func encodeUint32(v uint32) []byte {
	buf := make([]byte, uint32Size)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}
