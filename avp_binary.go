package radius

import (
	"fmt"
)

var avpBinary AvpBinary

type AvpBinary struct{}

func (s AvpBinary) Value(p *Packet, a AVP) interface{} {
	return a.Value
}
func (s AvpBinary) String(p *Packet, a AVP) string {
	return fmt.Sprintf("%#v", a.Value)
}
func (s AvpBinary) FromString(v string) []byte {
	return []byte(v)
}
