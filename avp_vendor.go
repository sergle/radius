package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrInvalidVendorFormat: the VSA format is unsupported or too small for the attribute number.
var ErrInvalidVendorFormat = errors.New("invalid vendor format")

type VendorID uint32

// VendorAttr is a vendor attribute number; formats with a 2- or 4-byte type use more than 8 bits.
type VendorAttr uint32

const (
	vendorIDLen = 4
	// WiMAX continuation byte flag: the value continues in the next attribute
	vsaContinued = 0x80
)

// VendorFormat is a vendor's VSA header layout, FreeRADIUS "VENDOR ... format=T,L[,c]".
type VendorFormat struct {
	TypeLen      uint8 // attribute number size: 1, 2 or 4
	LengthLen    uint8 // length field size: 1, 2 or 0 (the value fills the rest of the AVP)
	Continuation bool  // WiMAX continuation byte after the length
}

// DefaultVendorFormat is the RFC 2865 layout (format=1,1); a zero VendorFormat means the same.
var DefaultVendorFormat = VendorFormat{TypeLen: 1, LengthLen: 1}

// norm returns f, or DefaultVendorFormat if f is zero.
func (f VendorFormat) norm() VendorFormat {
	if f == (VendorFormat{}) {
		return DefaultVendorFormat
	}
	return f
}

// Valid reports whether f is a supported format; the zero value means format=1,1.
func (f VendorFormat) Valid() bool {
	f = f.norm()
	if f.TypeLen != 1 && f.TypeLen != 2 && f.TypeLen != 4 || f.LengthLen > 2 {
		return false
	}
	// FreeRADIUS allows continuation only with 1,1
	return !f.Continuation || f.TypeLen == 1 && f.LengthLen == 1
}

// headerLen returns the size of a vendor attribute header.
func (f VendorFormat) headerLen() int {
	n := int(f.TypeLen) + int(f.LengthLen)
	if f.Continuation {
		n++
	}
	return n
}

// maxValueLen returns the longest value that fits one Vendor-Specific AVP.
func (f VendorFormat) maxValueLen() int {
	return maxAVPValueLen - vendorIDLen - f.headerLen()
}

// tlvSupported reports whether f allows TLV sub-attributes (format=1,1 and 1,1,c).
func (f VendorFormat) tlvSupported() bool {
	return f.TypeLen == 1 && f.LengthLen == 1
}

// VSA is a vendor attribute; Format is the vendor's header layout, zero for format=1,1.
// ParseVSA returns an encrypted attribute with its plaintext Value, which Packet.AddVSA encrypts.
type VSA struct {
	Vendor VendorID
	Type   VendorAttr
	Value  []byte
	Format VendorFormat

	enc avpDataType // encrypted type of a plaintext Value, nil if Value is encoded
	tag uint8       // tag of an encrypted tagged Value
}

var avpVendor AvpVendor

type AvpVendor struct{}

func (s AvpVendor) Value(p *Packet, a AVP) any {
	// as-is
	return a.Value
}

// String formats a Vendor-Specific attribute with the default dictionary, otherwise raw.
func (s AvpVendor) String(p *Packet, a AVP) string {
	// DecodeAVPValue formats other "vsa" attributes with this method
	if d := GetDefaultDictionary(); d != nil && a.Type == AttrVendorSpecific {
		return d.DecodeAVPValue(p, a)
	}
	vsa, ok := decodeVSA(a, DefaultVendorFormat)
	if !ok {
		return avpBinary.String(p, a)
	}

	return rawVSAString(p, vsa, "", false)
}

func (s AvpVendor) FromString(v string) []byte {
	// not called directly
	return nil
}

// check reports an error if vsa's format is invalid or its type doesn't fit the format.
func (vsa VSA) check() error {
	f := vsa.Format.norm()
	if !f.Valid() {
		return fmt.Errorf("%w %+v", ErrInvalidVendorFormat, vsa.Format)
	}
	if f.TypeLen < 4 && uint64(vsa.Type) >= 1<<(8*f.TypeLen) {
		return fmt.Errorf("%w: attribute %d doesn't fit %d-byte type", ErrInvalidVendorFormat, vsa.Type, f.TypeLen)
	}
	return nil
}

// encodable reports an error if vsa can't be encoded without a packet.
func (vsa VSA) encodable() error {
	if vsa.enc != nil {
		return fmt.Errorf("%w, use Packet.AddVSA", ErrEncryptedAttribute)
	}
	return vsa.check()
}

// ToAVP encodes vsa as one Vendor-Specific AVP; use ToAVPList for long values with continuation.
// An invalid format or type, or a value to encrypt, is logged and gives the zero AVP.
func (vsa VSA) ToAVP() AVP {
	if err := vsa.encodable(); err != nil {
		logger().Warn("radius: VSA.ToAVP", "vendor", vsa.Vendor, "error", err)
		return AVP{}
	}
	return AVP{Type: AttrVendorSpecific, Value: appendVSA(nil, vsa.Vendor, vsa.Format.norm(), vsa.Type, false, vsa.Value)}
}

// ToAVPList is like ToAVP but splits a value too long for one AVP if the format has a continuation byte;
// an invalid format or type, or a value to encrypt, is logged and gives nil.
func (vsa VSA) ToAVPList() []AVP {
	if err := vsa.encodable(); err != nil {
		logger().Warn("radius: VSA.ToAVPList", "vendor", vsa.Vendor, "error", err)
		return nil
	}
	f := vsa.Format.norm()
	maxLen := f.maxValueLen()
	if !f.Continuation || len(vsa.Value) <= maxLen {
		return []AVP{vsa.ToAVP()}
	}
	var avps []AVP
	for v := vsa.Value; len(v) > 0; {
		n := min(len(v), maxLen)
		value := appendVSA(nil, vsa.Vendor, f, vsa.Type, n < len(v), v[:n])
		avps = append(avps, AVP{Type: AttrVendorSpecific, Value: value})
		v = v[n:]
	}
	return avps
}

// appendVSA appends a Vendor-Specific AVP value holding one vendor attribute to b.
func appendVSA(b []byte, vendor VendorID, f VendorFormat, typ VendorAttr, more bool, value []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(vendor))
	b = appendUint(b, uint32(typ), f.TypeLen)
	b = appendUint(b, uint32(f.headerLen()+len(value)), f.LengthLen)
	if f.Continuation {
		flags := byte(0)
		if more {
			flags = vsaContinued
		}
		b = append(b, flags)
	}
	return append(b, value...)
}

// appendUint appends the low size bytes of v, big-endian.
func appendUint(b []byte, v uint32, size uint8) []byte {
	for i := int(size) - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*i)))
	}
	return b
}

// readUint reads a big-endian number of up to 4 bytes.
func readUint(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v
}

// walkVSA calls fn for each vendor attribute of value (after the vendor id) until fn returns false;
// it reports false if value is malformed before that.
func walkVSA(value []byte, f VendorFormat, fn func(typ VendorAttr, more bool, v []byte) bool) bool {
	hdr := f.headerLen()
	for len(value) > 0 {
		if len(value) < hdr {
			return false
		}
		typ := VendorAttr(readUint(value[:f.TypeLen]))
		l := len(value)
		if f.LengthLen > 0 {
			l = int(readUint(value[f.TypeLen : f.TypeLen+f.LengthLen]))
			if l < hdr || l > len(value) {
				return false
			}
		}
		more := f.Continuation && value[hdr-1]&vsaContinued != 0
		if !fn(typ, more, value[hdr:l]) {
			return true
		}
		value = value[l:]
	}
	return true
}

// vsaVendor returns the vendor id of a Vendor-Specific value.
func vsaVendor(value []byte) (VendorID, bool) {
	if len(value) < vendorIDLen {
		return 0, false
	}
	return VendorID(binary.BigEndian.Uint32(value)), true
}

// ToVSA decodes the first vendor attribute of a, using the vendor format of the default dictionary.
func ToVSA(a AVP) *VSA {
	f := DefaultVendorFormat
	if vendor, ok := vsaVendor(a.Value); ok {
		if d := GetDefaultDictionary(); d != nil {
			f = d.VendorFormat(vendor)
		}
	}
	vsa, _ := decodeVSA(a, f)
	return vsa
}

// decodeVSA is like ToVSA with format f but also reports whether the first vendor attribute is well-formed.
func decodeVSA(a AVP, f VendorFormat) (*VSA, bool) {
	vsa := &VSA{Format: f}
	vendor, ok := vsaVendor(a.Value)
	if !ok {
		return vsa, false
	}
	vsa.Vendor = vendor
	rest := a.Value[vendorIDLen:]
	if len(rest) >= int(f.TypeLen) {
		vsa.Type = VendorAttr(readUint(rest[:f.TypeLen]))
	}
	found := false
	valid := walkVSA(rest, f, func(_ VendorAttr, _ bool, v []byte) bool {
		vsa.Value = append([]byte{}, v...)
		found = true
		return false
	})
	return vsa, valid && found
}

// eachVSA calls fn for each attribute of vendor in p until fn returns false;
// continued values are joined, an interrupted continuation yields the fragments seen.
func eachVSA(p *Packet, vendor VendorID, f VendorFormat, fn func(typ VendorAttr, v []byte) bool) {
	var pending []byte
	var pendingType VendorAttr
	continued, stop := false, false
	flush := func() bool {
		if !continued {
			return true
		}
		continued = false
		stop = !fn(pendingType, pending)
		return !stop
	}
	p.EachAVP(func(a AVP) bool {
		if v, ok := vsaVendor(a.Value); a.Type != AttrVendorSpecific || !ok || v != vendor {
			return flush()
		}
		walkVSA(a.Value[vendorIDLen:], f, func(typ VendorAttr, more bool, v []byte) bool {
			if continued && typ != pendingType && !flush() {
				return false
			}
			if more || continued {
				if !continued {
					pending, pendingType, continued = nil, typ, true
				}
				pending = append(pending, v...)
				if more {
					return true
				}
				continued = false
				v = pending
			}
			stop = !fn(typ, v)
			return !stop
		})
		return !stop
	})
	if !stop {
		flush()
	}
}
