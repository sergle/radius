package radius

import "net"

// etherLen is the size of an "ether" value, a 48-bit MAC address.
const etherLen = 6

var avpEther AvpEther

// AvpEther handles "ether" attributes; Value returns a net.HardwareAddr.
type AvpEther struct{}

func (s AvpEther) Value(p *Packet, a AVP) any {
	return net.HardwareAddr(a.Value)
}

// String formats the value as "00:11:22:aa:bb:cc".
func (s AvpEther) String(p *Packet, a AVP) string {
	if len(a.Value) != etherLen {
		return avpBinary.String(p, a)
	}
	return net.HardwareAddr(a.Value).String()
}

// FromString parses a MAC address in any net.ParseMAC form, or returns nil.
func (s AvpEther) FromString(v string) []byte {
	mac, err := net.ParseMAC(v)
	if err != nil || len(mac) != etherLen {
		return nil
	}
	return mac
}
