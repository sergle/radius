package radius

import (
	"encoding/binary"
	"reflect"
	"strconv"
)

type AvpUint32Enum struct {
	t interface{} // t should from a uint32 type like AcctStatusTypeEnum
}

func (s AvpUint32Enum) Value(p *Packet, a AVP) interface{} {
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	if len(a.Value) < 4 {
		return value.Interface()
	}
	value.SetUint(uint64(binary.BigEndian.Uint32(a.Value)))
	return value.Interface()
}
func (s AvpUint32Enum) String(p *Packet, a AVP) string {
	if len(a.Value) < 4 {
		return "invalid"
	}
	number := binary.BigEndian.Uint32(a.Value)
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	value.SetUint(uint64(number))
	method := value.MethodByName("String")
	if !method.IsValid() {
		return strconv.Itoa(int(number))
	}
	out := method.Call(nil)
	return out[0].Interface().(string)
}

// TODO
func (s AvpUint32Enum) FromString(v string) []byte {
	return []byte(v)
}
