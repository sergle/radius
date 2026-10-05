package radius

import (
	"encoding/binary"
)

type VendorID uint32

// TODO some VSA has uint16 type (Lucent)
type VendorAttr uint8

const (
	vendorIDLen   = 4
	vsaHeaderSize = vendorIDLen + 2 // vendor id + attr type + attr len
)

// Vendor
type VSA struct {
	Vendor VendorID
	Type   VendorAttr
	Value  []byte
}

var avpVendor AvpVendor

type AvpVendor struct{}

func (s AvpVendor) Value(p *Packet, a AVP) interface{} {
	// as-is
	return a.Value
}

// String formats a Vendor-Specific attribute with the default dictionary, otherwise raw.
func (s AvpVendor) String(p *Packet, a AVP) string {
	// DecodeAVPValue formats other "vsa" attributes with this method
	if d := GetDefaultDictionary(); d != nil && a.Type == AttrVendorSpecific {
		return d.DecodeAVPValue(p, a)
	}
	vsa, ok := decodeVSA(a)
	if !ok {
		return avpBinary.String(p, a)
	}

	return rawVSAString(vsa, "", false)
}

func (s AvpVendor) FromString(v string) []byte {
	// not called directly
	return nil
}

// encode VSA attribute under Vendor-Specific AVP
func (vsa VSA) ToAVP() AVP {
	vsaLen := len(vsa.Value)
	// vendor id (4) + attr type (1) + attr len (1)
	// TODO - for WiMAX vendor there is extra byte in VSA header
	vsaValue := make([]byte, vsaLen+vsaHeaderSize)
	binary.BigEndian.PutUint32(vsaValue[0:4], uint32(vsa.Vendor))
	// TODO VendorAttr -- 1 bytes or 2?
	vsaValue[4] = uint8(vsa.Type)
	vsaValue[5] = uint8(vsaLen + 2)
	copy(vsaValue[vsaHeaderSize:], vsa.Value)

	avp := AVP{Type: AttrVendorSpecific, Value: vsaValue}

	return avp
}

// decode AVP value to VSA
func ToVSA(a AVP) *VSA {
	vsa, _ := decodeVSA(a)
	return vsa
}

// decodeVSA is like ToVSA but also reports whether the VSA is well-formed.
func decodeVSA(a AVP) (*VSA, bool) {
	vsa := new(VSA)
	value := a.Value
	if len(value) < vsaHeaderSize {
		return vsa, false
	}
	vsa.Vendor = VendorID(binary.BigEndian.Uint32(value[0:vendorIDLen]))
	vsa.Type = VendorAttr(value[4])
	vsaLen := int(value[5])
	if vsaLen < 2 || vendorIDLen+vsaLen > len(value) {
		return vsa, false
	}
	vsa.Value = make([]byte, vsaLen-2)
	copy(vsa.Value, value[vsaHeaderSize:vendorIDLen+vsaLen])

	return vsa, true
}
