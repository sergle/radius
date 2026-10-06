package radius

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// RFC 3162 §2.3 value layout: reserved byte, prefix length, up to 16 prefix bytes.
const (
	ipv6PrefixHeaderLen = 2
	ipv6PrefixMaxLen    = ipv6PrefixHeaderLen + net.IPv6len
	ipv6PrefixMaxBits   = net.IPv6len * bitsPerByte
	bitsPerByte         = 8
	ipv6Wildcard        = "*" // FreeRADIUS wildcard address
)

var avpIPv6Prefix AvpIPv6Prefix

// AvpIPv6Prefix handles "ipv6prefix" attributes (RFC 3162), e.g. Framed-IPv6-Prefix.
// Value returns a netip.Prefix as received, host bits included (use Masked before comparing),
// or the zero Prefix if the value is malformed.
type AvpIPv6Prefix struct{}

func (s AvpIPv6Prefix) Value(p *Packet, a AVP) interface{} {
	prefix, _ := decodeIPv6Prefix(a.Value)
	return prefix
}

func (s AvpIPv6Prefix) String(p *Packet, a AVP) string {
	prefix, ok := decodeIPv6Prefix(a.Value)
	if !ok {
		return avpBinary.String(p, a)
	}
	return prefix.String()
}

// FromString encodes an IPv6 prefix like "2001:db8::/64", or an address as /128 ("*" is ::/128),
// with host bits cleared and all 16 prefix bytes, as FreeRADIUS does.
func (s AvpIPv6Prefix) FromString(v string) []byte {
	prefix, ok := parseIPv6Prefix(v)
	if !ok {
		return nil
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().As16()
	b := make([]byte, ipv6PrefixHeaderLen, ipv6PrefixMaxLen)
	b[1] = uint8(prefix.Bits())
	return append(b, addr[:]...)
}

// parseIPv6Prefix parses "addr/len" (decimal len, leading zeros allowed) or a bare address, like FreeRADIUS fr_pton6.
func parseIPv6Prefix(v string) (netip.Prefix, bool) {
	addrStr, bitsStr, hasBits := strings.Cut(v, "/")
	if !hasBits && addrStr == ipv6Wildcard {
		return netip.PrefixFrom(netip.IPv6Unspecified(), ipv6PrefixMaxBits), true
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil || !addr.Is6() || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	bits := ipv6PrefixMaxBits
	if hasBits {
		if bitsStr == "" || strings.Trim(bitsStr, "0123456789") != "" {
			return netip.Prefix{}, false
		}
		n, err := strconv.Atoi(bitsStr)
		if err != nil || n > ipv6PrefixMaxBits {
			return netip.Prefix{}, false
		}
		bits = n
	}
	return netip.PrefixFrom(addr, bits), true
}

// decodeIPv6Prefix parses value like FreeRADIUS: missing prefix bytes are zero, host bits and the reserved byte are kept as received.
func decodeIPv6Prefix(value []byte) (netip.Prefix, bool) {
	if len(value) < ipv6PrefixHeaderLen || len(value) > ipv6PrefixMaxLen || int(value[1]) > ipv6PrefixMaxBits {
		return netip.Prefix{}, false
	}
	var addr [net.IPv6len]byte
	copy(addr[:], value[ipv6PrefixHeaderLen:])
	return netip.PrefixFrom(netip.AddrFrom16(addr), int(value[1])), true
}
