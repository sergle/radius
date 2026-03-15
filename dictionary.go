package radius

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"

	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	// ASCII whitespace checker for RADIUS files (only space and tab)
)

// isSpace checks for ASCII space or tab characters.
var isSpace = func(r rune) bool { return r == ' ' || r == '\t' }

// splitLine splits a line into fields using ASCII whitespace without extra allocations.
func splitLine(line string) []string {
	var fields []string
	start := -1
	for i, r := range line {
		if isSpace(r) {
			if start != -1 {
				fields = append(fields, line[start:i])
				start = -1
			}
		} else {
			if start == -1 {
				start = i
			}
		}
	}
	if start != -1 {
		fields = append(fields, line[start:])
	}
	return fields
}

var (
	defaultDictionary   *Dictionary
	defaultDictionaryMu sync.RWMutex
)

func init() {
	defaultDictionary = NewDictionary()
}

// SetDefaultDictionary sets the dictionary used for package-level lookups (like AVP.Decode)
func SetDefaultDictionary(d *Dictionary) {
	defaultDictionaryMu.Lock()
	defer defaultDictionaryMu.Unlock()
	defaultDictionary = d
}

// GetDefaultDictionary returns the current default dictionary
func GetDefaultDictionary() *Dictionary {
	defaultDictionaryMu.RLock()
	defer defaultDictionaryMu.RUnlock()
	return defaultDictionary
}

type Dictionary struct {
	sync.RWMutex
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
	d.Lock()
	defer d.Unlock()
	return d.loadFileInternal(fname)
}

func (d *Dictionary) loadFileInternal(fname string) error {
	log.Printf("Reading file %s\n", fname)

	if _, ok := d.flist[fname]; ok {
		log.Printf("File %s already read\n", fname)
		return nil
	}

	d.flist[fname] = true

	file, err := os.Open(fname)
	if err != nil {
		log.Printf("Failed to open file %s, error %s\n", fname, err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		//log.Printf("Line: %s\n", line)

		err := d.parseLine(fname, line)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Dictionary) parseLine(fname string, line string) error {

	// ATTRIBUTE     User-Name                               1       string
	parts := splitLine(line)

	if len(parts) == 0 {
		return nil
	}

	if strings.HasPrefix(parts[0], "#") {
		return nil
	}

	cmd := parts[0]
	switch cmd {
	case "ATTRIBUTE":
		if len(parts) < 4 {
			return errors.New("Invalid ATTRIBUTE line: " + line)
		}
		return d.parseAttribute(parts[1], parts[2], parts[3])
	case "VALUE":
		if len(parts) < 4 {
			return errors.New("Invalid VALUE line: " + line)
		}
		return d.parseValue(parts[1], parts[2], parts[3])
	case "$INCLUDE":
		if len(parts) < 2 {
			return errors.New("Invalid $INCLUDE line: " + line)
		}
		return d.parseInclude(fname, parts[1])
	case "VENDOR":
		if len(parts) < 3 {
			return errors.New("Invalid VENDOR line: " + line)
		}
		return d.parseVendor(parts[1], parts[2])
	case "BEGIN-VENDOR":
		if len(parts) < 2 {
			return errors.New("Invalid BEGIN-VENDOR line: " + line)
		}
		return d.parseBeginVendor(parts[1])
	case "END-VENDOR":
		if len(parts) < 2 {
			return errors.New("Invalid END-VENDOR line: " + line)
		}
		return d.parseEndVendor(parts[1])
	case "BEGIN-TLV":
		if len(parts) < 2 {
			return errors.New("Invalid BEGIN-TLV line: " + line)
		}
		return d.parseBeginTLV(parts[1])
	case "END-TLV":
		if len(parts) < 2 {
			return errors.New("Invalid END-TLV line: " + line)
		}
		return d.parseEndTLV(parts[1])
	default:
		log.Printf("UNKNOWN cmd: %s\n", cmd)
		return errors.New("Unsupported command " + cmd)
	}

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
		log.Printf("Failed to convert attr %s id %s to uint: %s. Ignoring\n", attr_name, attr_id, err)
		// ignore errors
		return nil
	}

	//TODO WiMAX
	if d.current_tlv > 0 {
		// ignore tlv sub-attributes
		log.Printf("Ignore TVL attribute %s\n", attr_name)
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
		//log.Printf("Attr %s has id %d and type %s\n", attr_name, a_id, attr_type)
	}

	return nil
}

func (d *Dictionary) parseValue(attr_name string, const_name string, const_value string) error {
	//TODO WiMAX
	if d.current_tlv > 0 {
		// ignore tlv sub-attributes
		log.Printf("Ignore TVL attribute %s\n", attr_name)
		return nil
	}

	var present bool
	if d.current_vendor > 0 {
		_, present = d.vsa_attr_id[d.current_vendor][attr_name]
	} else {
		_, present = d.attr_id[attr_name]
	}

	if !present {
		log.Printf("Value %s for non-existing attribute %s\n", const_name, attr_name)
		// ignore 'compat' errors
		return nil
	}

	// some values defined as 0x.. - using '0' to auto-detect
	c_id, err := strconv.ParseUint(const_value, 0, 32)
	if err != nil {
		log.Printf("Failed to convert constant value to int: %s\n", err)
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
		//log.Printf("Attr %s has value %s = %s\n", attr_name, const_name, const_value)
	}

	return nil
}

var blacklist_dictionary = map[string]int{
	"dictionary.freeradius.internal": 1,
	"dictionary.compat":              1,
	"dictionary.usr.illegal":         1,
	"dictionary.vqp":                 1,
	// attribute id > 1byte
	"dictionary.lucent":  1,
	"dictionary.starent": 1,
	"dictionary.usr":     1,
}

func (d *Dictionary) parseInclude(fname string, inc_name string) error {
	// ignore files in unsupported format
	if _, ok := blacklist_dictionary[inc_name]; ok {
		log.Printf("Skip internal/unsupported FreeRADIUS dictionary: %s\n", inc_name)
		return nil
	}

	log.Printf("-- include file %s --\n", inc_name)
	// included file locate in the same directory
	full_name := filepath.Join(filepath.Dir(fname), inc_name)
	// clear vendor
	d.current_vendor = 0
	return d.loadFileInternal(full_name)
}

func (d *Dictionary) parseVendor(vendor_name string, vendor_id string) error {
	v_id, err := strconv.ParseUint(vendor_id, 0, 32)
	if err != nil {
		log.Printf("Failed to convert vendor id: %s\n", err)
		return err
	}

	d.vendor_id[vendor_name] = VendorID(v_id)
	d.vendor_name[VendorID(v_id)] = vendor_name

	return nil
}

func (d *Dictionary) parseBeginVendor(vendor_name string) error {
	v_id, ok := d.vendor_id[vendor_name]
	if !ok {
		log.Printf("vendor %s not found", vendor_name)
		return errors.New("unknown vendor " + vendor_name)
	}
	d.current_vendor = v_id
	return nil
}

func (d *Dictionary) parseEndVendor(vendor_name string) error {
	v_id, ok := d.vendor_id[vendor_name]
	if !ok {
		log.Printf("vendor %s not found", vendor_name)
		return errors.New("unknown vendor " + vendor_name)
	}

	if d.current_vendor == 0 || d.current_vendor != v_id {
		return errors.New("unexpected END-VENDOR found")
	}

	d.current_vendor = 0

	return nil
}

func (d *Dictionary) parseBeginTLV(attr_name string) error {
	a_id, ok := d.vsa_attr_id[d.current_vendor][attr_name]
	if !ok {
		log.Printf("TLV attribute %s not found\n", attr_name)
		return errors.New("Unknown TLV attribute " + attr_name)
	}
	d.current_tlv = a_id
	return nil
}

func (d *Dictionary) parseEndTLV(attr_name string) error {
	a_id, ok := d.vsa_attr_id[d.current_vendor][attr_name]
	if !ok {
		log.Printf("TLV attribute %s not found\n", attr_name)
		return errors.New("Unknown TLV attribute " + attr_name)
	}

	if d.current_tlv == 0 || d.current_tlv != a_id {
		log.Printf("Current TLV %d expected %d", d.current_tlv, a_id)
		return errors.New("unexpected END-TLV")
	}

	d.current_tlv = 0
	return nil
}

// attribute type to handler mapping
var attr_type_handlers = map[string]avpDataType{
	"integer":    avpUint32,
	"ipaddr":     avpIP,
	"string":     avpString,
	"octets":     avpBinary,
	"password":   avpPassword,
	"vsa":        avpVendor,
	"eapmessage": avpEapMessage,
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
	if a.Type == AttrUserPassword {
		return avpPassword.String(p, a)
	} else if a.Type == AttrVendorSpecific {
		vsa := ToVSA(a)

		vendor_name := d.GetVendorName(vsa.Vendor)
		attr_name := d.GetVSAAttributeName(vsa.Vendor, vsa.Type)
		attr_type := d.GetVSAAttributeType(vsa.Vendor, attr_name)
		handler := attr_type_handlers[attr_type]
		if handler == nil {
			handler = avpBinary
		}

		valStr := handler.String(p, AVP{Value: vsa.Value})
		// Try to lookup enum name for VSAs too
		if attr_type == "integer" {
			vID := binary.BigEndian.Uint32(vsa.Value)
			d.RLock()
			if d.vsa_const_name[vsa.Vendor] != nil && d.vsa_const_name[vsa.Vendor][attr_name] != nil {
				if enumName, ok := d.vsa_const_name[vsa.Vendor][attr_name][vID]; ok {
					valStr = enumName
				}
			}
			d.RUnlock()
		}

		return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
			vendor_name, vsa.Vendor, attr_name, vsa.Type, valStr)

	}

	attr_name := d.GetAttributeName(a.Type)
	attr_type := d.GetAttributeType(attr_name)
	handler := attr_type_handlers[attr_type]
	if handler == nil {
		handler = avpBinary
	}

	// Try to lookup enum name for standard attributes
	if attr_type == "integer" {
		vID := binary.BigEndian.Uint32(a.Value)
		d.RLock()
		if d.const_name[attr_name] != nil {
			if enumName, ok := d.const_name[attr_name][vID]; ok {
				d.RUnlock()
				return enumName
			}
		}
		d.RUnlock()
	}

	return handler.String(p, a)
}

// public

func (d *Dictionary) GetAttributeID(attr_name string) AttributeType {
	d.RLock()
	defer d.RUnlock()
	return d.attr_id[attr_name]
}

func (d *Dictionary) HasAttribute(attr_name string) bool {
	d.RLock()
	defer d.RUnlock()
	_, present := d.attr_id[attr_name]
	return present
}

func (d *Dictionary) GetAttributeName(attr_id AttributeType) string {
	d.RLock()
	defer d.RUnlock()
	return d.attr_name[attr_id]
}

func (d *Dictionary) GetAttributeType(attr_name string) string {
	d.RLock()
	defer d.RUnlock()
	return d.attr_type[attr_name]
}

func (d *Dictionary) GetVSAAttributeID(vendor_id VendorID, attr_name string) VendorAttr {
	d.RLock()
	defer d.RUnlock()
	return d.vsa_attr_id[vendor_id][attr_name]
}

func (d *Dictionary) HasVSAAttribute(vendor_id VendorID, attr_name string) bool {
	d.RLock()
	defer d.RUnlock()
	_, present := d.vsa_attr_id[vendor_id][attr_name]
	return present
}

func (d *Dictionary) GetVSAAttributeName(vendor_id VendorID, attr_id VendorAttr) string {
	d.RLock()
	defer d.RUnlock()
	return d.vsa_attr_name[vendor_id][attr_id]
}

func (d *Dictionary) GetVSAAttributeType(vendor_id VendorID, attr_name string) string {
	d.RLock()
	defer d.RUnlock()
	return d.vsa_attr_type[vendor_id][attr_name]
}

func (d *Dictionary) GetVendorName(vendor_id VendorID) string {
	d.RLock()
	defer d.RUnlock()
	return d.vendor_name[vendor_id]
}

func (d *Dictionary) GetVendorID(vendor_name string) VendorID {
	d.RLock()
	defer d.RUnlock()
	return d.vendor_id[vendor_name]
}

func (d *Dictionary) NewAVP(attr_name string, attr_value string) AVP {
	attr_id := d.GetAttributeID(attr_name)
	attr_type := d.GetAttributeType(attr_name)
	handler := attr_type_handlers[attr_type]
	if handler == nil {
		log.Printf("Unknown type %s\n", attr_type)
		return AVP{}
	}

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
