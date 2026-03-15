package radius

import (
	"net"
)

var avpIP AvpIP

type AvpIP struct{}

func (s AvpIP) Value(p *Packet, a AVP) interface{} {
	return net.IP(a.Value)
}
func (s AvpIP) String(p *Packet, a AVP) string {
	return net.IP(a.Value).String()
}
func (s AvpIP) FromString(v string) []byte {
	ip := net.ParseIP(v)
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}
