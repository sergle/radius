package radius

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"
)

type Dictionary struct {
	// map attribute name to id
	attr_id map[string]AttributeType
	// map attribute it to name
	attr_name map[AttributeType]string
	// map attribute name to type name
	attr_type map[string]string
	// map attribute name + enum name to id
	const_id map[string]map[string]uint32
	// map attribute name + enum id to enum name
	const_name map[string]map[uint32]string
	// list of scanned files - to avoid recursion
	flist map[string]bool
	// map vendor name to id
	vendor_id map[string]VendorID
	// map vendor id to name
	vendor_name map[VendorID]string
	// current vendor (parser state)
	current_vendor VendorID
	// current TLV attribute (WiMAX Vendor), ignored
	current_tlv VendorAttr

	// vsa
	// vendor -> attribute name -> attribute id
	vsa_attr_id   map[VendorID]map[string]VendorAttr
	vsa_attr_name map[VendorID]map[VendorAttr]string
	vsa_attr_type map[VendorID]map[string]string
	// vendor -> attribute name -> constant name -> constant id
	vsa_const_id   map[VendorID]map[string]map[string]uint32
	vsa_const_name map[VendorID]map[string]map[uint32]string
}

func NewDictionary() *Dictionary {
	dict := &Dictionary{}

	dict.attr_id = make(map[string]AttributeType)
	dict.attr_name = make(map[AttributeType]string)
	dict.attr_type = make(map[string]string)
	dict.const_id = make(map[string]map[string]uint32)
	dict.const_name = make(map[string]map[uint32]string)
	dict.flist = make(map[string]bool)
	dict.vendor_id = make(map[string]VendorID)
	dict.vendor_name = make(map[VendorID]string)
	dict.vsa_attr_id = make(map[VendorID]map[string]VendorAttr)
	dict.vsa_attr_name = make(map[VendorID]map[VendorAttr]string)
	dict.vsa_attr_type = make(map[VendorID]map[string]string)
	dict.vsa_const_id = make(map[VendorID]map[string]map[string]uint32)
	dict.vsa_const_name = make(map[VendorID]map[string]map[uint32]string)

	return dict
}

func (d *Dictionary) LoadFile(fname string) error {
	fmt.Printf("Reading file %s\n", fname)

	if _, ok := d.flist[fname]; ok {
		fmt.Printf("File %s already read\n", fname)
		return nil
	}

	d.flist[fname] = true

	file, err := os.Open(fname)
	if err != nil {
		fmt.Printf("Failed to open file %s, error %s\n", fname, err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Printf("Line: %s\n", line)

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		err := d.parseLine(fname, line)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Dictionary) parseLine(fname string, line string) error {

	// ATTRIBUTE     User-Name                               1       string
	parts := strings.FieldsFunc(line, func(c rune) bool { return unicode.IsSpace(c) })

	if len(parts) == 0 {
		return nil
	}

	cmd := parts[0]
	switch cmd {
	case "ATTRIBUTE":
		return d.parseAttribute(parts[1], parts[2], parts[3])
	case "VALUE":
		return d.parseValue(parts[1], parts[2], parts[3])
	case "$INCLUDE":
		return d.parseInclude(fname, parts[1])
	case "VENDOR":
		return d.parseVendor(parts[1], parts[2])
	case "BEGIN-VENDOR":
		return d.parseBeginVendor(parts[1])
	case "END-VENDOR":
		return d.parseEndVendor(parts[1])
	case "BEGIN-TLV":
		return d.parseBeginTLV(parts[1])
	case "END-TLV":
		return d.parseEndTLV(parts[1])
	default:
		fmt.Printf("UNKNOWN cmd: %s\n", cmd)
		return errors.New("Unsupported command " + cmd)
	}

	return nil
}

func (d *Dictionary) parseAttribute(attr_name string, attr_id string, attr_type string) error {
	// id_size := 8
	// if d.current_vendor > 0 {
	//     // some vendors has 16-bit attr id (Lucent)
	//     id_size = 16
	// }

	// 0 - guess base (0x for hex)
	a_id, err := strconv.ParseUint(attr_id, 0, 8)
	if err != nil {
		fmt.Printf("Failed to convert attr %s id %s to uint: %s. Ignoring\n", attr_name, attr_id, err)
		// ignore errors
		return nil
	}

	//TODO WiMAX
	if d.current_tlv > 0 {
		// ignore tlv sub-attributes
		fmt.Printf("Ignore TVL attribute %s\n", attr_name)
		return nil
	}

	if d.current_vendor > 0 {
		if _, ok := d.vsa_attr_id[d.current_vendor]; !ok {
			d.vsa_attr_id[d.current_vendor] = make(map[string]VendorAttr)
			d.vsa_attr_name[d.current_vendor] = make(map[VendorAttr]string)
			d.vsa_attr_type[d.current_vendor] = make(map[string]string)
		}

		d.vsa_attr_id[d.current_vendor][attr_name] = VendorAttr(a_id)
		d.vsa_attr_name[d.current_vendor][VendorAttr(a_id)] = attr_name
		d.vsa_attr_type[d.current_vendor][attr_name] = attr_type
		//fmt.Printf("Attr %s / %s has id %d and type %s\n", d.vendor_name[ d.current_vendor ], attr_name, a_id, attr_type)
	} else {
		d.attr_id[attr_name] = AttributeType(a_id)
		d.attr_name[AttributeType(a_id)] = attr_name
		d.attr_type[attr_name] = attr_type
		//fmt.Printf("Attr %s has id %d and type %s\n", attr_name, a_id, attr_type)
	}

	return nil
}

func (d *Dictionary) parseValue(attr_name string, const_name string, const_value string) error {
	//TODO WiMAX
	if d.current_tlv > 0 {
		// ignore tlv sub-attributes
		fmt.Printf("Ignore TVL attribute %s\n", attr_name)
		return nil
	}

	var present bool
	if d.current_vendor > 0 {
		present = d.HasVSAAttribute(d.current_vendor, attr_name)
	} else {
		present = d.HasAttribute(attr_name)
	}

	if !present {
		fmt.Printf("Value %s for non-existing attribute %s\n", const_name, attr_name)
		// ignore 'compat' errors
		return nil
	}

	// some values defined as 0x.. - using '0' to auto-detect
	c_id, err := strconv.ParseUint(const_value, 0, 32)
	if err != nil {
		fmt.Printf("Failed to convert constant value to int: %s\n", err)
		return err
	}

	if d.current_vendor > 0 {
		if _, ok := d.vsa_const_id[d.current_vendor]; !ok {
			d.vsa_const_id[d.current_vendor] = make(map[string]map[string]uint32)
			d.vsa_const_name[d.current_vendor] = make(map[string]map[uint32]string)
		}

		if _, ok := d.vsa_const_id[d.current_vendor][attr_name]; !ok {
			d.vsa_const_id[d.current_vendor][attr_name] = make(map[string]uint32)
			d.vsa_const_name[d.current_vendor][attr_name] = make(map[uint32]string)
		}

		d.vsa_const_id[d.current_vendor][attr_name][const_name] = uint32(c_id)
		d.vsa_const_name[d.current_vendor][attr_name][uint32(c_id)] = const_name
		//fmt.Printf("Attr %s / %s has value %s = %s\n", d.vendor_name[ d.current_vendor ], attr_name, const_name, const_value)
	} else {
		if _, exist := d.const_id[attr_name]; !exist {
			d.const_id[attr_name] = make(map[string]uint32)
			d.const_name[attr_name] = make(map[uint32]string)
		}

		d.const_id[attr_name][const_name] = uint32(c_id)
		d.const_name[attr_name][uint32(c_id)] = const_name
		//fmt.Printf("Attr %s has value %s = %s\n", attr_name, const_name, const_value)
	}

	return nil
}

func (d *Dictionary) parseInclude(fname string, inc_name string) error {
	fmt.Printf("-- include file %s --\n", inc_name)
	// included file locate in the same directory
	full_name := path.Join(path.Dir(fname), inc_name)
	// clear vendor
	d.current_vendor = 0
	return d.LoadFile(full_name)
}

func (d *Dictionary) parseVendor(vendor_name string, vendor_id string) error {
	v_id, err := strconv.ParseUint(vendor_id, 0, 32)
	if err != nil {
		fmt.Printf("Failed to convert vendor id: %s\n", err)
		return err
	}

	d.vendor_id[vendor_name] = VendorID(v_id)
	d.vendor_name[VendorID(v_id)] = vendor_name

	return nil
}

func (d *Dictionary) parseBeginVendor(vendor_name string) error {
	v_id, ok := d.vendor_id[vendor_name]
	if !ok {
		fmt.Printf("Vendor %s not found", vendor_name)
		return errors.New("Unknown vendor " + vendor_name)
	}
	d.current_vendor = v_id
	return nil
}

func (d *Dictionary) parseEndVendor(vendor_name string) error {
	v_id, ok := d.vendor_id[vendor_name]
	if !ok {
		fmt.Printf("Vendor %s not found", vendor_name)
		return errors.New("Unknown vendor " + vendor_name)
	}

	if d.current_vendor == 0 || d.current_vendor != v_id {
		return errors.New("Unexpected END-VENDOR found")
	}

	d.current_vendor = 0

	return nil
}

func (d *Dictionary) parseBeginTLV(attr_name string) error {
	a_id, ok := d.vsa_attr_id[d.current_vendor][attr_name]
	if !ok {
		fmt.Printf("TLV attribute %s not found\n", attr_name)
		return errors.New("Unknown TLV attribute " + attr_name)
	}
	d.current_tlv = a_id
	return nil
}

func (d *Dictionary) parseEndTLV(attr_name string) error {
	a_id, ok := d.vsa_attr_id[d.current_vendor][attr_name]
	if !ok {
		fmt.Printf("TLV attribute %s not found\n", attr_name)
		return errors.New("Unknown TLV attribute " + attr_name)
	}

	if d.current_tlv == 0 || d.current_tlv != a_id {
		fmt.Printf("Current TLV %d expected %d", d.current_tlv, a_id)
		return errors.New("Unexpected END-TLV")
	}

	d.current_tlv = 0
	return nil
}

// attribute type to handler mapping
var attr_type_handlers = map[string]avpDataType{
	"integer": avpUint32,
	"ipaddr":  avpIP,
	"string":  avpString,
	"octets":  avpBinary,
	// "byte"
	// "ipv6addr"
	// "short"
	// "date"
	// "tlv"
	// "combo-ip"
	// "ether"
	// "abinary"
	// "ifid"
	// "signed"
	// "ipv6prefix"
}

func (d *Dictionary) DecodeAVPValue(p *Packet, a AVP) string {
	if a.Type == UserPassword {
		return avpPassword.String(p, a)
	} else if a.Type == VendorSpecific {
		vsa := ToVSA(a)

		vendor_name := d.GetVendorName(vsa.Vendor)
		attr_name := d.GetVSAAttributeName(vsa.Vendor, vsa.Type)
		attr_type := d.GetVSAAttributeType(vsa.Vendor, attr_name)
		handler := attr_type_handlers[attr_type]

		return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
			vendor_name, vsa.Vendor, attr_name, vsa.Type, handler.String(p, AVP{Value: vsa.Value}))

	}

	attr_name := d.GetAttributeName(a.Type)
	attr_type := d.GetAttributeType(attr_name)
	handler := attr_type_handlers[attr_type]
	return handler.String(p, a)
}

// public

func (d *Dictionary) GetAttributeID(attr_name string) AttributeType {
	return d.attr_id[attr_name]
}

func (d *Dictionary) HasAttribute(attr_name string) bool {
	_, present := d.attr_id[attr_name]
	return present
}

func (d *Dictionary) GetAttributeName(attr_id AttributeType) string {
	return d.attr_name[attr_id]
}

func (d *Dictionary) GetAttributeType(attr_name string) string {
	return d.attr_type[attr_name]
}

func (d *Dictionary) GetVSAAttributeID(vendor_id VendorID, attr_name string) VendorAttr {
	return d.vsa_attr_id[vendor_id][attr_name]
}

func (d *Dictionary) HasVSAAttribute(vendor_id VendorID, attr_name string) bool {
	_, present := d.vsa_attr_id[vendor_id][attr_name]
	return present
}

func (d *Dictionary) GetVSAAttributeName(vendor_id VendorID, attr_id VendorAttr) string {
	return d.vsa_attr_name[vendor_id][attr_id]
}

func (d *Dictionary) GetVSAAttributeType(vendor_id VendorID, attr_name string) string {
	return d.vsa_attr_type[vendor_id][attr_name]
}

func (d *Dictionary) GetVendorName(vendor_id VendorID) string {
	return d.vendor_name[vendor_id]
}

func (d *Dictionary) GetVendorID(vendor_name string) VendorID {
	return d.vendor_id[vendor_name]
}

func (d *Dictionary) NewAVP(attr_name string, attr_value string) AVP {
	attr_id := d.GetAttributeID(attr_name)
	attr_type := d.GetAttributeType(attr_name)
	handler := attr_type_handlers[attr_type]

	value := handler.FromString(attr_value)

	avp := AVP{Type: attr_id, Value: value}
	return avp
}

func (d *Dictionary) NewVSA(vendor_name string, attr_name string, attr_value string) VSA {
	vendor_id := d.GetVendorID(vendor_name)
	attr_id := d.GetVSAAttributeID(vendor_id, attr_name)
	attr_type := d.GetVSAAttributeType(vendor_id, attr_name)
	handler := attr_type_handlers[attr_type]

	value := handler.FromString(attr_value)

	vsa := VSA{Vendor: vendor_id, Type: attr_id, Value: value}
	return vsa
}
