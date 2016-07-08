package radius

import (
	"encoding/binary"
	"fmt"
)

type VendorID uint32

//TODO some VSA has uint16 type (Lucent)
type VendorAttr uint8

// Vendor
type VSA struct {
	Vendor VendorID
	Type   VendorAttr
	Value  []byte
}

var avpVendor avpVendort

type avpVendort struct{}

func (s avpVendort) Value(p *Packet, a AVP) interface{} {
	// as-is
	return a.Value
}

func (s avpVendort) String(p *Packet, a AVP) string {
	vsa := ToVSA(a)

	return fmt.Sprintf("{Vendor: %d, Attr: %d, Value: %#v}", vsa.Vendor, vsa.Type, vsa.Value)
}

func (s avpVendort) FromString(v string) []byte {
	// not called directly
	return nil
}

// encode VSA attribute under Vendor-Specific AVP
func (vsa VSA) ToAVP() AVP {
	vsa_len := len(vsa.Value)
	// vendor id (4) + attr type (1) + attr len (1)
	// TODO - for WiMAX vendor there is extra byte in VSA header
	vsa_value := make([]byte, vsa_len+6)
	binary.BigEndian.PutUint32(vsa_value[0:4], uint32(vsa.Vendor))
	// TODO VendorAttr -- 1 bytes or 2?
	vsa_value[4] = uint8(vsa.Type)
	vsa_value[5] = uint8(vsa_len + 2)
	copy(vsa_value[6:], vsa.Value)

	avp := AVP{Type: VendorSpecific, Value: vsa_value}

	return avp
}

// decode AVP value to VSA
func ToVSA(a AVP) *VSA {
	vsa := new(VSA)
	value := a.Value
	vsa.Vendor = VendorID(binary.BigEndian.Uint32(value[0:4]))
	vsa.Type = VendorAttr(value[4])
	vsa.Value = make([]byte, value[5]-2)
	copy(vsa.Value, value[6:])

	return vsa
}
