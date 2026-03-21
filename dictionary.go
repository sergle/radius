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

// Dictionary parses and stores FreeRADIUS-style dictionary files.
//
// A Dictionary provides name/type mappings for standard attributes and
// Vendor-Specific Attributes (VSAs), and is used by AVP decoding/formatting.
type Dictionary struct {
	sync.RWMutex
	// map attribute name to id
	attrID map[string]AttributeType
	// map attribute it to name
	attrName map[AttributeType]string
	// map attribute name to type name
	attrType map[string]string
	// map attribute name + enum name to id
	constID map[string]map[string]uint32
	// map attribute name + enum id to enum name
	constName map[string]map[uint32]string
	// list of scanned files - to avoid recursion
	fileList map[string]bool
	// map vendor name to id
	vendorID map[string]VendorID
	// map vendor id to name
	vendorName map[VendorID]string
	// current vendor (parser state)
	currentVendor VendorID
	// current TLV attribute (WiMAX Vendor), ignored
	currentTLV VendorAttr

	// vsa
	// vendor -> attribute name -> attribute id
	vsaAttrID   map[VendorID]map[string]VendorAttr
	vsaAttrName map[VendorID]map[VendorAttr]string
	vsaAttrType map[VendorID]map[string]string
	// vendor -> attribute name -> constant name -> constant id
	vsaConstID   map[VendorID]map[string]map[string]uint32
	vsaConstName map[VendorID]map[string]map[uint32]string
}

// NewDictionary returns an empty dictionary ready to load dictionary files.
func NewDictionary() *Dictionary {
	dict := &Dictionary{}

	dict.attrID = make(map[string]AttributeType)
	dict.attrName = make(map[AttributeType]string)
	dict.attrType = make(map[string]string)
	dict.constID = make(map[string]map[string]uint32)
	dict.constName = make(map[string]map[uint32]string)
	dict.fileList = make(map[string]bool)
	dict.vendorID = make(map[string]VendorID)
	dict.vendorName = make(map[VendorID]string)
	dict.vsaAttrID = make(map[VendorID]map[string]VendorAttr)
	dict.vsaAttrName = make(map[VendorID]map[VendorAttr]string)
	dict.vsaAttrType = make(map[VendorID]map[string]string)
	dict.vsaConstID = make(map[VendorID]map[string]map[string]uint32)
	dict.vsaConstName = make(map[VendorID]map[string]map[uint32]string)

	return dict
}

// LoadFile loads and parses a dictionary file.
//
// The file format is compatible with FreeRADIUS dictionary files and supports
// $INCLUDE recursion (with internal/unsupported files skipped).
func (d *Dictionary) LoadFile(fname string) error {
	d.Lock()
	defer d.Unlock()
	return d.loadFileInternal(fname)
}

func (d *Dictionary) loadFileInternal(fname string) error {
	log.Printf("Reading file %s\n", fname)

	if _, ok := d.fileList[fname]; ok {
		log.Printf("File %s already read\n", fname)
		return nil
	}

	d.fileList[fname] = true

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

func (d *Dictionary) parseAttribute(attrName string, attrID string, attrType string) error {
	// id_size := 8
	// if d.current_vendor > 0 {
	//     // some vendors has 16-bit attr id (Lucent)
	//     id_size = 16
	// }

	// 0 - guess base (0x for hex)
	aID, err := strconv.ParseUint(attrID, 0, 8)
	if err != nil {
		log.Printf("Failed to convert attr %s id %s to uint: %s. Ignoring\n", attrName, attrID, err)
		// ignore errors
		return nil
	}

	//TODO WiMAX
	if d.currentTLV > 0 {
		// ignore tlv sub-attributes
		log.Printf("Ignore TVL attribute %s\n", attrName)
		return nil
	}

	if d.currentVendor > 0 {
		if _, ok := d.vsaAttrID[d.currentVendor]; !ok {
			d.vsaAttrID[d.currentVendor] = make(map[string]VendorAttr)
			d.vsaAttrName[d.currentVendor] = make(map[VendorAttr]string)
			d.vsaAttrType[d.currentVendor] = make(map[string]string)
		}

		d.vsaAttrID[d.currentVendor][attrName] = VendorAttr(aID)
		d.vsaAttrName[d.currentVendor][VendorAttr(aID)] = attrName
		d.vsaAttrType[d.currentVendor][attrName] = attrType
		//fmt.Printf("Attr %s / %s has id %d and type %s\n", d.vendorName[ d.currentVendor ], attrName, aID, attrType)
	} else {
		d.attrID[attrName] = AttributeType(aID)
		d.attrName[AttributeType(aID)] = attrName
		d.attrType[attrName] = attrType
		//log.Printf("Attr %s has id %d and type %s\n", attrName, aID, attrType)
	}

	return nil
}

func (d *Dictionary) parseValue(attrName string, constName string, constValue string) error {
	//TODO WiMAX
	if d.currentTLV > 0 {
		// ignore tlv sub-attributes
		log.Printf("Ignore TVL attribute %s\n", attrName)
		return nil
	}

	var present bool
	if d.currentVendor > 0 {
		_, present = d.vsaAttrID[d.currentVendor][attrName]
	} else {
		_, present = d.attrID[attrName]
	}

	if !present {
		log.Printf("Value %s for non-existing attribute %s\n", constName, attrName)
		// ignore 'compat' errors
		return nil
	}

	// some values defined as 0x.. - using '0' to auto-detect
	cID, err := strconv.ParseUint(constValue, 0, 32)
	if err != nil {
		log.Printf("Failed to convert constant value to int: %s\n", err)
		return err
	}

	if d.currentVendor > 0 {
		if _, ok := d.vsaConstID[d.currentVendor]; !ok {
			d.vsaConstID[d.currentVendor] = make(map[string]map[string]uint32)
			d.vsaConstName[d.currentVendor] = make(map[string]map[uint32]string)
		}

		if _, ok := d.vsaConstID[d.currentVendor][attrName]; !ok {
			d.vsaConstID[d.currentVendor][attrName] = make(map[string]uint32)
			d.vsaConstName[d.currentVendor][attrName] = make(map[uint32]string)
		}

		d.vsaConstID[d.currentVendor][attrName][constName] = uint32(cID)
		d.vsaConstName[d.currentVendor][attrName][uint32(cID)] = constName
		//fmt.Printf("Attr %s / %s has value %s = %s\n", d.vendorName[ d.currentVendor ], attrName, constName, constValue)
	} else {
		if _, exist := d.constID[attrName]; !exist {
			d.constID[attrName] = make(map[string]uint32)
			d.constName[attrName] = make(map[uint32]string)
		}

		d.constID[attrName][constName] = uint32(cID)
		d.constName[attrName][uint32(cID)] = constName
		//log.Printf("Attr %s has value %s = %s\n", attrName, constName, constValue)
	}

	return nil
}

var blacklistDictionary = map[string]int{
	"dictionary.freeradius.internal": 1,
	"dictionary.compat":              1,
	"dictionary.usr.illegal":         1,
	"dictionary.vqp":                 1,
	// attribute id > 1byte
	"dictionary.lucent":  1,
	"dictionary.starent": 1,
	"dictionary.usr":     1,
}

func (d *Dictionary) parseInclude(fname string, incName string) error {
	// ignore files in unsupported format
	if _, ok := blacklistDictionary[incName]; ok {
		log.Printf("Skip internal/unsupported FreeRADIUS dictionary: %s\n", incName)
		return nil
	}

	log.Printf("-- include file %s --\n", incName)
	// included file locate in the same directory
	fullName := filepath.Join(filepath.Dir(fname), incName)
	// clear vendor
	d.currentVendor = 0
	return d.loadFileInternal(fullName)
}

func (d *Dictionary) parseVendor(vendorName string, vendorID string) error {
	vID, err := strconv.ParseUint(vendorID, 0, 32)
	if err != nil {
		log.Printf("Failed to convert vendor id: %s\n", err)
		return err
	}

	d.vendorID[vendorName] = VendorID(vID)
	d.vendorName[VendorID(vID)] = vendorName

	return nil
}

func (d *Dictionary) parseBeginVendor(vendorName string) error {
	vID, ok := d.vendorID[vendorName]
	if !ok {
		log.Printf("vendor %s not found", vendorName)
		return errors.New("unknown vendor " + vendorName)
	}
	d.currentVendor = vID
	return nil
}

func (d *Dictionary) parseEndVendor(vendorName string) error {
	vID, ok := d.vendorID[vendorName]
	if !ok {
		log.Printf("vendor %s not found", vendorName)
		return errors.New("unknown vendor " + vendorName)
	}

	if d.currentVendor == 0 || d.currentVendor != vID {
		return errors.New("unexpected END-VENDOR found")
	}

	d.currentVendor = 0

	return nil
}

func (d *Dictionary) parseBeginTLV(attrName string) error {
	aID, ok := d.vsaAttrID[d.currentVendor][attrName]
	if !ok {
		log.Printf("TLV attribute %s not found\n", attrName)
		return errors.New("Unknown TLV attribute " + attrName)
	}
	d.currentTLV = aID
	return nil
}

func (d *Dictionary) parseEndTLV(attrName string) error {
	aID, ok := d.vsaAttrID[d.currentVendor][attrName]
	if !ok {
		log.Printf("TLV attribute %s not found\n", attrName)
		return errors.New("Unknown TLV attribute " + attrName)
	}

	if d.currentTLV == 0 || d.currentTLV != aID {
		log.Printf("Current TLV %d expected %d", d.currentTLV, aID)
		return errors.New("unexpected END-TLV")
	}

	d.currentTLV = 0
	return nil
}

// attribute type to handler mapping
var attrTypeHandlers = map[string]avpDataType{
	"integer":    avpUint32,
	"ipaddr":     avpIP,
	"ipv6addr":   avpIP,
	"string":     avpString,
	"octets":     avpBinary,
	"password":   avpPassword,
	"vsa":        avpVendor,
	"eapmessage": avpEapMessage,
	// "byte"
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

// DecodeAVPValue returns a human-readable string for the given AVP.
//
// When possible, DecodeAVPValue uses dictionary type information and enum
// mappings (including VSA enums) to format values.
func (d *Dictionary) DecodeAVPValue(p *Packet, a AVP) string {
	if a.Type == AttrUserPassword {
		return avpPassword.String(p, a)
	} else if a.Type == AttrVendorSpecific {
		vsa := ToVSA(a)

		vendorName := d.GetVendorName(vsa.Vendor)
		attrName := d.GetVSAAttributeName(vsa.Vendor, vsa.Type)
		attrType := d.GetVSAAttributeType(vsa.Vendor, attrName)
		handler := attrTypeHandlers[attrType]
		if handler == nil {
			handler = avpBinary
		}

		valStr := handler.String(p, AVP{Value: vsa.Value})
		// Try to lookup enum name for VSAs too
		if attrType == "integer" {
			vID := binary.BigEndian.Uint32(vsa.Value)
			d.RLock()
			if d.vsaConstName[vsa.Vendor] != nil && d.vsaConstName[vsa.Vendor][attrName] != nil {
				if enumName, ok := d.vsaConstName[vsa.Vendor][attrName][vID]; ok {
					valStr = enumName
				}
			}
			d.RUnlock()
		}

		return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
			vendorName, vsa.Vendor, attrName, vsa.Type, valStr)

	}

	attrName := d.GetAttributeName(a.Type)
	attrType := d.GetAttributeType(attrName)
	handler := attrTypeHandlers[attrType]
	if handler == nil {
		handler = avpBinary
	}

	// Try to lookup enum name for standard attributes
	if attrType == "integer" {
		vID := binary.BigEndian.Uint32(a.Value)
		d.RLock()
		if d.constName[attrName] != nil {
			if enumName, ok := d.constName[attrName][vID]; ok {
				d.RUnlock()
				return enumName
			}
		}
		d.RUnlock()
	}

	return handler.String(p, a)
}

// public

// GetAttributeID returns the AttributeType for an attribute name.
func (d *Dictionary) GetAttributeID(attrName string) AttributeType {
	d.RLock()
	defer d.RUnlock()
	return d.attrID[attrName]
}

// HasAttribute reports whether the dictionary defines the given attribute name.
func (d *Dictionary) HasAttribute(attrName string) bool {
	d.RLock()
	defer d.RUnlock()
	_, present := d.attrID[attrName]
	return present
}

// GetAttributeName returns the attribute name for an AttributeType.
func (d *Dictionary) GetAttributeName(attrID AttributeType) string {
	d.RLock()
	defer d.RUnlock()
	return d.attrName[attrID]
}

// GetAttributeType returns the type name (for example "string" or "integer")
// for an attribute name.
func (d *Dictionary) GetAttributeType(attrName string) string {
	d.RLock()
	defer d.RUnlock()
	return d.attrType[attrName]
}

// GetVSAAttributeID returns the vendor-specific attribute ID for a vendor and attribute name.
func (d *Dictionary) GetVSAAttributeID(vendorID VendorID, attrName string) VendorAttr {
	d.RLock()
	defer d.RUnlock()
	return d.vsaAttrID[vendorID][attrName]
}

// HasVSAAttribute reports whether the dictionary defines the given vendor-specific attribute.
func (d *Dictionary) HasVSAAttribute(vendorID VendorID, attrName string) bool {
	d.RLock()
	defer d.RUnlock()
	_, present := d.vsaAttrID[vendorID][attrName]
	return present
}

// GetVSAAttributeName returns the attribute name for a vendor-specific attribute ID.
func (d *Dictionary) GetVSAAttributeName(vendorID VendorID, attrID VendorAttr) string {
	d.RLock()
	defer d.RUnlock()
	return d.vsaAttrName[vendorID][attrID]
}

// GetVSAAttributeType returns the type name (for example "string" or "integer")
// for a vendor-specific attribute.
func (d *Dictionary) GetVSAAttributeType(vendorID VendorID, attrName string) string {
	d.RLock()
	defer d.RUnlock()
	return d.vsaAttrType[vendorID][attrName]
}

// GetVendorName returns the vendor name for a VendorID.
func (d *Dictionary) GetVendorName(vendorID VendorID) string {
	d.RLock()
	defer d.RUnlock()
	return d.vendorName[vendorID]
}

// GetVendorID returns the VendorID for a vendor name.
func (d *Dictionary) GetVendorID(vendorName string) VendorID {
	d.RLock()
	defer d.RUnlock()
	return d.vendorID[vendorName]
}

// NewAVP constructs an AVP from the attribute name and a string value using
// the attribute type defined in the dictionary.
func (d *Dictionary) NewAVP(attrName string, attrValue string) AVP {
	attrID := d.GetAttributeID(attrName)
	attrType := d.GetAttributeType(attrName)
	handler := attrTypeHandlers[attrType]
	if handler == nil {
		log.Printf("Unknown type %s\n", attrType)
		return AVP{}
	}

	value := handler.FromString(attrValue)

	avp := AVP{Type: attrID, Value: value}
	return avp
}

// NewVSA constructs a Vendor-Specific Attribute from the vendor name, attribute
// name, and a string value using the VSA type defined in the dictionary.
func (d *Dictionary) NewVSA(vendorName string, attrName string, attrValue string) VSA {
	vendorID := d.GetVendorID(vendorName)
	attrID := d.GetVSAAttributeID(vendorID, attrName)
	attrType := d.GetVSAAttributeType(vendorID, attrName)
	handler := attrTypeHandlers[attrType]

	value := handler.FromString(attrValue)

	vsa := VSA{Vendor: vendorID, Type: attrID, Value: value}
	return vsa
}
