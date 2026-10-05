package radius

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

type AvpUint32Enum struct {
	t interface{} // t should from a uint32 type like AcctStatusTypeEnum
}

// enum returns n converted to the type of s.t; reflection only for types outside this package.
func (s AvpUint32Enum) enum(n uint32) interface{} {
	switch s.t.(type) {
	case uint32:
		return n
	case AcctStatusTypeEnum:
		return AcctStatusTypeEnum(n)
	case NASPortTypeEnum:
		return NASPortTypeEnum(n)
	case ServiceTypeEnum:
		return ServiceTypeEnum(n)
	case PromptEnum:
		return PromptEnum(n)
	case TunnelTypeEnum:
		return TunnelTypeEnum(n)
	case TunnelMediumTypeEnum:
		return TunnelMediumTypeEnum(n)
	case AcctTerminateCauseEnum:
		return AcctTerminateCauseEnum(n)
	}
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	value.SetUint(uint64(n))
	return value.Interface()
}

func (s AvpUint32Enum) Value(p *Packet, a AVP) interface{} {
	if len(a.Value) < 4 {
		return s.enum(0)
	}
	return s.enum(binary.BigEndian.Uint32(a.Value))
}
func (s AvpUint32Enum) String(p *Packet, a AVP) string {
	if len(a.Value) < 4 {
		return "invalid"
	}
	number := binary.BigEndian.Uint32(a.Value)
	if v, ok := s.enum(number).(fmt.Stringer); ok {
		return v.String()
	}
	return strconv.Itoa(int(number))
}

// TODO
func (s AvpUint32Enum) FromString(v string) []byte {
	return []byte(v)
}
