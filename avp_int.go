package radius

import (
	"encoding/binary"
	"strconv"
)

const (
	uint8Size  = 1
	uint16Size = 2
	int32Size  = 4
)

var (
	avpUint8  AvpUint8
	avpUint16 AvpUint16
	avpInt32  AvpInt32
)

// AvpUint8 handles the "byte" type; Value returns uint32 like "integer" so VALUE names and callers share one type.
type AvpUint8 struct{}

func (s AvpUint8) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) != uint8Size {
		return uint32(0)
	}
	return uint32(a.Value[0])
}

func (s AvpUint8) String(p *Packet, a AVP) string {
	if len(a.Value) != uint8Size {
		return "invalid"
	}
	return strconv.Itoa(int(a.Value[0]))
}

func (s AvpUint8) FromString(value string) []byte {
	i, _ := strconv.ParseUint(value, 0, 8)
	return []byte{uint8(i)}
}

// AvpUint16 handles the "short" type (big-endian); Value returns uint32 like "integer".
type AvpUint16 struct{}

func (s AvpUint16) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) != uint16Size {
		return uint32(0)
	}
	return uint32(binary.BigEndian.Uint16(a.Value))
}

func (s AvpUint16) String(p *Packet, a AVP) string {
	if len(a.Value) != uint16Size {
		return "invalid"
	}
	return strconv.Itoa(int(binary.BigEndian.Uint16(a.Value)))
}

func (s AvpUint16) FromString(value string) []byte {
	i, _ := strconv.ParseUint(value, 0, 16)
	return binary.BigEndian.AppendUint16(nil, uint16(i))
}

// AvpInt32 handles the "signed" type (two's complement, big-endian); Value returns int32.
type AvpInt32 struct{}

func (s AvpInt32) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) != int32Size {
		return int32(0)
	}
	return int32(binary.BigEndian.Uint32(a.Value))
}

func (s AvpInt32) String(p *Packet, a AVP) string {
	if len(a.Value) != int32Size {
		return "invalid"
	}
	return strconv.Itoa(int(int32(binary.BigEndian.Uint32(a.Value))))
}

func (s AvpInt32) FromString(value string) []byte {
	i, _ := strconv.ParseInt(value, 0, 32)
	return encodeUint32(uint32(i))
}
