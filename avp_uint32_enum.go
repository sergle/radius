package radius

import (
	"encoding/binary"
	"reflect"
	"strconv"
)

type avpUint32Enum struct {
	t interface{} // t should from a uint32 type like AcctStatusTypeEnum
}

func (s avpUint32Enum) Value(p *Packet, a AVP) interface{} {
	value := reflect.New(reflect.TypeOf(s.t)).Elem()
	value.SetUint(uint64(binary.BigEndian.Uint32(a.Value)))
	return value.Interface()
}
func (s avpUint32Enum) String(p *Packet, a AVP) string {
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
func (s avpUint32Enum) FromString(v string) []byte {
	return []byte(v)
}
