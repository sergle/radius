package radius

import (
	"encoding/binary"
	"fmt"
)

type VendorID uint32

// TODO some VSA has uint16 type (Lucent)
type VendorAttr uint8

const vsaHeaderSize = 6

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

func (s AvpVendor) String(p *Packet, a AVP) string {
	vsa := ToVSA(a)

	return fmt.Sprintf("{Vendor: %d, Attr: %d, Value: %#v}", vsa.Vendor, vsa.Type, vsa.Value)
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
	vsa := new(VSA)
	value := a.Value
	if len(value) < vsaHeaderSize {
		return vsa
	}
	vsa.Vendor = VendorID(binary.BigEndian.Uint32(value[0:4]))
	vsa.Type = VendorAttr(value[4])
	vsaLen := int(value[5])
	if vsaLen < 2 || 4+vsaLen > len(value) {
		return vsa
	}
	vsa.Value = make([]byte, vsaLen-2)
	copy(vsa.Value, value[vsaHeaderSize:4+vsaLen])

	return vsa
}
