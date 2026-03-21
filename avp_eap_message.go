package radius

import (
	"fmt"
)

var avpEapMessage AvpEapMessage

type AvpEapMessage struct{}

func (s AvpEapMessage) Value(p *Packet, a AVP) interface{} {
	eap, err := EapDecode(a.Value)
	if err != nil {
		//TODO error handle
		fmt.Println("EapDecode fail ", err)
		return nil
	}
	return eap

}

func (s AvpEapMessage) String(p *Packet, a AVP) string {
	eap := s.Value(p, a)
	if eap == nil {
		return "nil"
	}
	return eap.(*EapPacket).String()
}

func (s AvpEapMessage) FromString(v string) []byte {
	return []byte(v)
}
