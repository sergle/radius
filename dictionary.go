package radius

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrUnknownAttribute         = errors.New("unknown attribute")
	ErrUnknownVendor            = errors.New("unknown vendor")
	ErrUnsupportedAttributeType = errors.New("unsupported attribute type")
	ErrInvalidValue             = errors.New("invalid attribute value")
	ErrEncryptedAttribute       = errors.New("encrypted attribute needs a packet, use AddPassword")
	ErrInvalidTag               = errors.New("invalid tag")
)

//go:embed dictionary.builtin
var builtinDictionaryData []byte

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

var defaultDictionary atomic.Pointer[Dictionary]

func init() {
	defaultDictionary.Store(NewDictionary())
}

// SetDefaultDictionary sets the dictionary used for package-level lookups (like AVP.Decode)
func SetDefaultDictionary(d *Dictionary) {
	defaultDictionary.Store(d)
}

// GetDefaultDictionary returns the current default dictionary
func GetDefaultDictionary() *Dictionary {
	return defaultDictionary.Load()
}

// Dictionary parses and stores FreeRADIUS-style dictionary files.
//
// A Dictionary provides name/type mappings for standard attributes and
// Vendor-Specific Attributes (VSAs), and is used by AVP decoding/formatting.
type Dictionary struct {
	mu sync.RWMutex
	// map attribute name to id
	attrID map[string]AttributeType
	// map attribute it to name
	attrName map[AttributeType]string
	// map attribute name to type name
	attrType map[string]string
	// map attribute name to flags column options
	attrFlags map[string]attributeFlags
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
	vsaAttrID    map[VendorID]map[string]VendorAttr
	vsaAttrName  map[VendorID]map[VendorAttr]string
	vsaAttrType  map[VendorID]map[string]string
	vsaAttrFlags map[VendorID]map[string]attributeFlags
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
	dict.attrFlags = make(map[string]attributeFlags)
	dict.constID = make(map[string]map[string]uint32)
	dict.constName = make(map[string]map[uint32]string)
	dict.fileList = make(map[string]bool)
	dict.vendorID = make(map[string]VendorID)
	dict.vendorName = make(map[VendorID]string)
	dict.vsaAttrID = make(map[VendorID]map[string]VendorAttr)
	dict.vsaAttrName = make(map[VendorID]map[VendorAttr]string)
	dict.vsaAttrType = make(map[VendorID]map[string]string)
	dict.vsaAttrFlags = make(map[VendorID]map[string]attributeFlags)
	dict.vsaConstID = make(map[VendorID]map[string]map[string]uint32)
	dict.vsaConstName = make(map[VendorID]map[string]map[uint32]string)

	return dict
}

// LoadFile loads and parses a dictionary file.
//
// The file format is compatible with FreeRADIUS dictionary files and supports
// $INCLUDE recursion (with internal/unsupported files skipped).
func (d *Dictionary) LoadFile(fname string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadFileInternal(fname)
}

func (d *Dictionary) loadFileInternal(fname string) error {
	logger().Debug("radius: reading dictionary file", "file", fname)

	if _, ok := d.fileList[fname]; ok {
		logger().Debug("radius: dictionary file already read", "file", fname)
		return nil
	}

	d.fileList[fname] = true

	file, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return d.loadReader(fname, file)
}

func (d *Dictionary) loadReader(name string, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if err := d.parseLine(name, scanner.Text()); err != nil {
			return err
		}
	}

	return nil
}

// LoadBuiltin loads the embedded built-in dictionary into d.
func (d *Dictionary) LoadBuiltin() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadReader("dictionary.builtin", bytes.NewReader(builtinDictionaryData))
}

func (d *Dictionary) parseLine(fname string, line string) error {

	// ATTRIBUTE     User-Name                               1       string  [flags]
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
		flags := ""
		if len(parts) > 4 {
			flags = parts[4]
		}
		return d.parseAttribute(parts[1], parts[2], parts[3], flags)
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
		return errors.New("Unsupported command " + cmd)
	}

}

// FreeRADIUS "encrypt=" methods.
const (
	encryptNone           = 0
	encryptUserPassword   = 1 // RFC 2865 section 5.2
	encryptTunnelPassword = 2 // RFC 2868 section 3.5
	encryptAscendSecret   = 3
)

// attributeFlags holds the ATTRIBUTE flags column (e.g. "has_tag,encrypt=2").
type attributeFlags struct {
	encrypt int
	hasTag  bool
}

// parseAttributeFlags parses the flags column; unknown options are ignored.
func parseAttributeFlags(attrName string, flags string) attributeFlags {
	var f attributeFlags
	if flags == "" {
		return f
	}
	for _, opt := range strings.Split(flags, ",") {
		name, value, _ := strings.Cut(opt, "=")
		switch name {
		case "has_tag":
			f.hasTag = true
		case "encrypt":
			n, err := strconv.Atoi(value)
			if err != nil {
				logger().Warn("radius: ignoring invalid encrypt flag", "attribute", attrName, "value", value)
				continue
			}
			if n > encryptAscendSecret {
				logger().Warn("radius: unknown encrypt method, treating as octets", "attribute", attrName, "encrypt", n)
			}
			f.encrypt = n
		}
	}
	return f
}

// effectiveType returns the handler type for attrType given its encrypt method.
func (f attributeFlags) effectiveType(attrType string) string {
	if f.encrypt == encryptNone {
		if f.hasTag {
			switch attrType {
			case typeInteger:
				return typeTaggedInteger
			case typeString, typeOctets:
				return typeTaggedString
			}
		}
		return attrType
	}
	if attrType != typeString && attrType != typeOctets {
		return attrType
	}
	switch f.encrypt {
	case encryptUserPassword:
		return typePassword
	case encryptTunnelPassword:
		return typeTunnelPassword
	case encryptAscendSecret:
		// Not decrypted yet; don't present ciphertext as text.
		return typeOctets
	}
	// unknown method, warned about in parseAttributeFlags
	return typeOctets
}

func (d *Dictionary) parseAttribute(attrName string, attrID string, attrType string, flags string) error {
	// id_size := 8
	// if d.current_vendor > 0 {
	//     // some vendors has 16-bit attr id (Lucent)
	//     id_size = 16
	// }

	// 0 - guess base (0x for hex)
	aID, err := strconv.ParseUint(attrID, 0, 8)
	if err != nil {
		logger().Warn("radius: ignoring attribute with invalid id", "attribute", attrName, "id", attrID, "error", err)
		// ignore errors
		return nil
	}

	//TODO WiMAX
	if d.currentTLV > 0 {
		// ignore tlv sub-attributes
		logger().Debug("radius: ignoring TLV sub-attribute", "attribute", attrName)
		return nil
	}

	f := parseAttributeFlags(attrName, flags)
	attrType = f.effectiveType(attrType)

	if d.currentVendor > 0 {
		if _, ok := d.vsaAttrID[d.currentVendor]; !ok {
			d.vsaAttrID[d.currentVendor] = make(map[string]VendorAttr)
			d.vsaAttrName[d.currentVendor] = make(map[VendorAttr]string)
			d.vsaAttrType[d.currentVendor] = make(map[string]string)
			d.vsaAttrFlags[d.currentVendor] = make(map[string]attributeFlags)
		}

		d.vsaAttrID[d.currentVendor][attrName] = VendorAttr(aID)
		d.vsaAttrName[d.currentVendor][VendorAttr(aID)] = attrName
		d.vsaAttrType[d.currentVendor][attrName] = attrType
		d.vsaAttrFlags[d.currentVendor][attrName] = f
	} else {
		d.attrID[attrName] = AttributeType(aID)
		d.attrName[AttributeType(aID)] = attrName
		d.attrType[attrName] = attrType
		d.attrFlags[attrName] = f
	}

	return nil
}

func (d *Dictionary) parseValue(attrName string, constName string, constValue string) error {
	//TODO WiMAX
	if d.currentTLV > 0 {
		// ignore tlv sub-attributes
		logger().Debug("radius: ignoring TLV sub-attribute", "attribute", attrName)
		return nil
	}

	var present bool
	if d.currentVendor > 0 {
		_, present = d.vsaAttrID[d.currentVendor][attrName]
	} else {
		_, present = d.attrID[attrName]
	}

	if !present {
		logger().Warn("radius: ignoring value for unknown attribute", "attribute", attrName, "value", constName)
		// ignore 'compat' errors
		return nil
	}

	// some values defined as 0x.. - using '0' to auto-detect
	cID, err := strconv.ParseUint(constValue, 0, 32)
	if err != nil {
		return fmt.Errorf("value %s of attribute %s: %w", constName, attrName, err)
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
	} else {
		if _, exist := d.constID[attrName]; !exist {
			d.constID[attrName] = make(map[string]uint32)
			d.constName[attrName] = make(map[uint32]string)
		}

		d.constID[attrName][constName] = uint32(cID)
		d.constName[attrName][uint32(cID)] = constName
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
		logger().Debug("radius: skipping unsupported dictionary", "file", incName)
		return nil
	}

	fullName := incName
	if !filepath.IsAbs(incName) {
		fullName = filepath.Join(filepath.Dir(fname), incName)
	}
	// clear vendor
	d.currentVendor = 0
	return d.loadFileInternal(fullName)
}

func (d *Dictionary) parseVendor(vendorName string, vendorID string) error {
	vID, err := strconv.ParseUint(vendorID, 0, 32)
	if err != nil {
		return fmt.Errorf("vendor %s: %w", vendorName, err)
	}

	d.vendorID[vendorName] = VendorID(vID)
	d.vendorName[VendorID(vID)] = vendorName

	return nil
}

func (d *Dictionary) parseBeginVendor(vendorName string) error {
	vID, ok := d.vendorID[vendorName]
	if !ok {
		return errors.New("unknown vendor " + vendorName)
	}
	d.currentVendor = vID
	return nil
}

func (d *Dictionary) parseEndVendor(vendorName string) error {
	vID, ok := d.vendorID[vendorName]
	if !ok {
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
		return errors.New("Unknown TLV attribute " + attrName)
	}
	d.currentTLV = aID
	return nil
}

func (d *Dictionary) parseEndTLV(attrName string) error {
	aID, ok := d.vsaAttrID[d.currentVendor][attrName]
	if !ok {
		return errors.New("Unknown TLV attribute " + attrName)
	}

	if d.currentTLV == 0 || d.currentTLV != aID {
		return fmt.Errorf("unexpected END-TLV %s: current TLV %d, expected %d", attrName, d.currentTLV, aID)
	}

	d.currentTLV = 0
	return nil
}

// dictionary attribute type names
const (
	typeInteger        = "integer"
	typeIPAddr         = "ipaddr"
	typeIPv6Addr       = "ipv6addr"
	typeString         = "string"
	typeOctets         = "octets"
	typePassword       = "password"
	typeTunnelPassword = "tunnel-password"
	typeTaggedInteger  = "tagged-integer"
	typeTaggedString   = "tagged-string"
	typeVSA            = "vsa"
	typeEAPMessage     = "eapmessage"
)

// attribute type to handler mapping
var attrTypeHandlers = map[string]avpDataType{
	typeInteger:        avpUint32,
	typeIPAddr:         avpIP,
	typeIPv6Addr:       avpIP,
	typeString:         avpString,
	typeOctets:         avpBinary,
	typePassword:       avpPassword,
	typeTunnelPassword: avpTunnelPassword,
	typeTaggedInteger:  avpTaggedUint32,
	typeTaggedString:   avpTaggedString,
	typeVSA:            avpVendor,
	typeEAPMessage:     avpEapMessage,
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

// handlerForValue returns the handler for attrType, or avpBinary if value is too short for it.
func handlerForValue(attrType string, value []byte) avpDataType {
	handler := attrTypeHandlers[attrType]
	if handler == nil || ((handler == avpUint32 || handler == avpTaggedUint32) && len(value) < uint32Size) {
		return avpBinary
	}
	return handler
}

// DecodeAVPValue returns a human-readable string for the given AVP.
//
// When possible, DecodeAVPValue uses dictionary type information and enum
// mappings (including VSA enums) to format values.
func (d *Dictionary) DecodeAVPValue(p *Packet, a AVP) string {
	if a.Type == AttrUserPassword {
		return avpPassword.String(p, a)
	} else if a.Type == AttrVendorSpecific {
		vsa, ok := decodeVSA(a)
		if !ok {
			return avpBinary.String(p, a)
		}

		d.mu.RLock()
		vendorName := d.vendorName[vsa.Vendor]
		attrName := d.vsaAttrName[vsa.Vendor][vsa.Type]
		handler := handlerForValue(d.vsaAttrType[vsa.Vendor][attrName], vsa.Value)
		// Try to lookup enum name for VSAs too
		valStr, ok := enumName(handler, vsa.Value, d.vsaConstName[vsa.Vendor][attrName])
		d.mu.RUnlock()
		if !ok {
			valStr = handler.String(p, AVP{Value: vsa.Value})
		}

		return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
			vendorName, vsa.Vendor, attrName, vsa.Type, valStr)

	}

	d.mu.RLock()
	attrName := d.attrName[a.Type]
	handler := handlerForValue(d.attrType[attrName], a.Value)
	// Try to lookup enum name for standard attributes
	name, ok := enumName(handler, a.Value, d.constName[attrName])
	d.mu.RUnlock()
	if ok {
		return name
	}

	return handler.String(p, a)
}

// enumName returns the VALUE name of an integer value, with its tag if any; caller holds the lock.
func enumName(handler avpDataType, value []byte, names map[uint32]string) (string, bool) {
	if handler != avpUint32 && handler != avpTaggedUint32 {
		return "", false
	}
	v := handler.Value(nil, AVP{Value: value}).(uint32)
	name, ok := names[v]
	if ok && handler == avpTaggedUint32 {
		name = withTag(name, value[0])
	}
	return name, ok
}

// attrDesc returns the name and type name of attribute t under one read lock.
func (d *Dictionary) attrDesc(t AttributeType) (name, attrType string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	name = d.attrName[t]
	return name, d.attrType[name]
}

// public

// GetAttributeID returns the AttributeType for an attribute name.
func (d *Dictionary) GetAttributeID(attrName string) AttributeType {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.attrID[attrName]
}

// HasAttribute reports whether the dictionary defines the given attribute name.
func (d *Dictionary) HasAttribute(attrName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, present := d.attrID[attrName]
	return present
}

// GetAttributeName returns the attribute name for an AttributeType.
func (d *Dictionary) GetAttributeName(attrID AttributeType) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.attrName[attrID]
}

// GetAttributeType returns the type name (for example "string" or "integer")
// for an attribute name.
func (d *Dictionary) GetAttributeType(attrName string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.attrType[attrName]
}

// GetVSAAttributeID returns the vendor-specific attribute ID for a vendor and attribute name.
func (d *Dictionary) GetVSAAttributeID(vendorID VendorID, attrName string) VendorAttr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vsaAttrID[vendorID][attrName]
}

// HasVSAAttribute reports whether the dictionary defines the given vendor-specific attribute.
func (d *Dictionary) HasVSAAttribute(vendorID VendorID, attrName string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, present := d.vsaAttrID[vendorID][attrName]
	return present
}

// GetVSAAttributeName returns the attribute name for a vendor-specific attribute ID.
func (d *Dictionary) GetVSAAttributeName(vendorID VendorID, attrID VendorAttr) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vsaAttrName[vendorID][attrID]
}

// GetVSAAttributeType returns the type name (for example "string" or "integer")
// for a vendor-specific attribute.
func (d *Dictionary) GetVSAAttributeType(vendorID VendorID, attrName string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vsaAttrType[vendorID][attrName]
}

// GetVendorName returns the vendor name for a VendorID.
func (d *Dictionary) GetVendorName(vendorID VendorID) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vendorName[vendorID]
}

// GetVendorID returns the VendorID for a vendor name.
func (d *Dictionary) GetVendorID(vendorName string) VendorID {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.vendorID[vendorName]
}

// NewAVP is like ParseAVP but logs the error and returns the zero AVP.
func (d *Dictionary) NewAVP(attrName string, attrValue string) AVP {
	avp, err := d.ParseAVP(attrName, attrValue)
	if err != nil {
		logger().Warn("radius: NewAVP", "error", err)
	}
	return avp
}

// NewVSA is like ParseVSA but logs the error and returns the zero VSA.
func (d *Dictionary) NewVSA(vendorName string, attrName string, attrValue string) VSA {
	vsa, err := d.ParseVSA(vendorName, attrName, attrValue)
	if err != nil {
		logger().Warn("radius: NewVSA", "error", err)
	}
	return vsa
}

// ParseAVP constructs an AVP from the attribute name and a string value using
// the attribute type defined in the dictionary. Integer values may be VALUE names.
func (d *Dictionary) ParseAVP(attrName string, attrValue string) (AVP, error) {
	attrName, tag, tagged, err := splitTagName(attrName)
	if err != nil {
		return AVP{}, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	attrID, ok := d.attrID[attrName]
	if !ok {
		return AVP{}, fmt.Errorf("%w: %s", ErrUnknownAttribute, attrName)
	}
	attrType := d.attrType[attrName]
	handler := attrTypeHandlers[attrType]
	if handler == nil {
		return AVP{}, fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, attrType, attrName)
	}
	if tagged && !isTagged(handler) {
		return AVP{}, fmt.Errorf("%w: attribute %s has no tag", ErrInvalidTag, attrName)
	}
	value, err := encodeValue(handler, d.constID[attrName], tag, attrValue)
	if err != nil {
		return AVP{}, fmt.Errorf("%w for attribute %s", err, attrName)
	}
	return AVP{Type: attrID, Value: value}, nil
}

// ParseVSA constructs a Vendor-Specific Attribute from the vendor name, attribute
// name, and a string value using the VSA type defined in the dictionary.
func (d *Dictionary) ParseVSA(vendorName string, attrName string, attrValue string) (VSA, error) {
	attrName, tag, tagged, err := splitTagName(attrName)
	if err != nil {
		return VSA{}, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	vendorID, vendorOK := d.vendorID[vendorName]
	attrID, attrOK := d.vsaAttrID[vendorID][attrName]
	attrType := d.vsaAttrType[vendorID][attrName]
	if !vendorOK {
		return VSA{}, fmt.Errorf("%w: %s", ErrUnknownVendor, vendorName)
	}
	if !attrOK {
		return VSA{}, fmt.Errorf("%w: %s/%s", ErrUnknownAttribute, vendorName, attrName)
	}
	handler := attrTypeHandlers[attrType]
	if handler == nil {
		return VSA{}, fmt.Errorf("%w %q for attribute %s/%s", ErrUnsupportedAttributeType, attrType, vendorName, attrName)
	}
	if tagged && !isTagged(handler) {
		return VSA{}, fmt.Errorf("%w: attribute %s/%s has no tag", ErrInvalidTag, vendorName, attrName)
	}
	value, err := encodeValue(handler, d.vsaConstID[vendorID][attrName], tag, attrValue)
	if err != nil {
		return VSA{}, fmt.Errorf("%w for attribute %s/%s", err, vendorName, attrName)
	}
	return VSA{Vendor: vendorID, Type: attrID, Value: value}, nil
}

// encodeValue encodes value with handler; integers accept a VALUE name from names or a number.
func encodeValue(handler avpDataType, names map[string]uint32, tag uint8, value string) ([]byte, error) {
	switch handler {
	case avpPassword, avpTunnelPassword:
		return nil, ErrEncryptedAttribute
	case avpTaggedString:
		return encodeTaggedString(tag, value), nil
	case avpUint32, avpTaggedUint32:
		return encodeInteger(handler == avpTaggedUint32, names, tag, value)
	}
	return handler.FromString(value), nil
}

// encodeInteger encodes a VALUE name from names or a number; tagged integers have 24 bits.
func encodeInteger(tagged bool, names map[string]uint32, tag uint8, value string) ([]byte, error) {
	v, known := names[value]
	if !known {
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		v = uint32(n)
	}
	if tagged {
		if v > taggedIntMax {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		v |= uint32(tag) << 24
	}
	return encodeUint32(v), nil
}
