package radius

import (
	"net"
	"net/netip"
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

var avpIPv6 AvpIPv6

// AvpIPv6 is AvpIP for "ipv6addr" attributes; FromString accepts only IPv6 addresses.
type AvpIPv6 struct{ AvpIP }

func (s AvpIPv6) FromString(v string) []byte {
	ip, err := netip.ParseAddr(v)
	if err != nil || !ip.Is6() || ip.Zone() != "" {
		return nil
	}
	b := ip.As16()
	return b[:]
}

var avpComboIP AvpComboIP

// AvpComboIP handles "combo-ip" attributes: an IPv4 or IPv6 address, told apart by length.
type AvpComboIP struct{ AvpIP }

func (s AvpComboIP) String(p *Packet, a AVP) string {
	if len(a.Value) != net.IPv4len && len(a.Value) != net.IPv6len {
		return avpBinary.String(p, a)
	}
	return s.AvpIP.String(p, a)
}

// FromString encodes an IPv4 address as 4 bytes and an IPv6 address as 16, or returns nil.
func (s AvpComboIP) FromString(v string) []byte {
	ip, err := netip.ParseAddr(v)
	if err != nil || ip.Zone() != "" {
		return nil
	}
	return ip.Unmap().AsSlice()
}
