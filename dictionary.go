package radius

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
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
	ErrEncryptedAttribute       = errors.New("encrypted attribute needs a packet")
	ErrInvalidTag               = errors.New("invalid tag")
	ErrNilPacket                = errors.New("nil packet")
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
	// open BEGIN-TLV blocks (parser state)
	tlvStack []tlvBlock
	// TLV attributes and sub-attributes: vendor (0 for standard) -> name -> definition
	tlvAttrs map[VendorID]map[string]*tlvAttr
	// vendors with a VSA format other than 1,1
	vendorFormat map[VendorID]VendorFormat
	// names of ignored sub-attributes, their VALUEs are skipped quietly
	skippedAttrs map[VendorID]map[string]bool
	// RFC 6929 extended attributes: vendor (0, or the vendor of EVS attributes) -> name -> definition
	extAttrs map[VendorID]map[string]*extAttr
	// vendor -> number -> definition used for decoding
	extNums map[VendorID]map[extKey]*extAttr
	// Extended-Vendor-Specific attribute of the open BEGIN-VENDOR format= block (parser state)
	evsBlock *extAttr

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
	dict.tlvAttrs = make(map[VendorID]map[string]*tlvAttr)
	dict.vendorFormat = make(map[VendorID]VendorFormat)
	dict.skippedAttrs = make(map[VendorID]map[string]bool)
	dict.extAttrs = make(map[VendorID]map[string]*extAttr)
	dict.extNums = make(map[VendorID]map[extKey]*extAttr)

	return dict
}

// LoadFile loads and parses a dictionary file.
//
// The file format is compatible with FreeRADIUS dictionary files and supports
// $INCLUDE recursion (with internal/unsupported files skipped).
//
// On error d may be partly loaded, and loading blocks lookups in d; to update
// the default dictionary, load into a NewDictionary and swap it in with
// SetDefaultDictionary.
func (d *Dictionary) LoadFile(fname string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.load(func() error { return d.loadFileInternal(fname) })
}

// load runs f; on error it forgets the files read, so they can be loaded again, and resets the parser state.
func (d *Dictionary) load(f func() error) error {
	files := maps.Clone(d.fileList)
	if err := f(); err != nil {
		d.fileList = files
		d.currentVendor, d.tlvStack, d.evsBlock = 0, nil, nil
		return err
	}
	return nil
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

	depth := len(d.tlvStack)
	for scanner.Scan() {
		if err := d.parseLine(name, scanner.Text()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if len(d.tlvStack) > depth {
		return fmt.Errorf("%s: missing END-TLV %s", name, d.tlvStack[len(d.tlvStack)-1].name)
	}
	return nil
}

// LoadBuiltin loads the embedded built-in dictionary into d; see LoadFile.
func (d *Dictionary) LoadBuiltin() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.load(func() error {
		return d.loadReader("dictionary.builtin", bytes.NewReader(builtinDictionaryData))
	})
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
		format := ""
		if len(parts) > 3 && !strings.HasPrefix(parts[3], "#") {
			format = parts[3]
		}
		return d.parseVendor(parts[1], parts[2], format)
	case "BEGIN-VENDOR":
		if len(parts) < 2 {
			return errors.New("Invalid BEGIN-VENDOR line: " + line)
		}
		option := ""
		if len(parts) > 2 && !strings.HasPrefix(parts[2], "#") {
			option = parts[2]
		}
		return d.parseBeginVendor(parts[1], option)
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

// encryptNames maps FreeRADIUS v4 "encrypt=" names to methods.
var encryptNames = map[string]int{
	"User-Password":   encryptUserPassword,
	"Tunnel-Password": encryptTunnelPassword,
	"Ascend-Secret":   encryptAscendSecret,
}

// v4TypeAliases maps FreeRADIUS v4 type names to their v3 equivalents.
var v4TypeAliases = map[string]string{
	"uint8":    typeByte,
	"uint16":   typeShort,
	"uint32":   typeInteger,
	"uint64":   "integer64",
	"int32":    typeSigned,
	"ipv4addr": typeIPAddr,
}

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
			n, ok := encryptNames[value]
			if !ok {
				var err error
				n, err = strconv.Atoi(value)
				if err != nil {
					logger().Warn("radius: ignoring invalid encrypt flag", "attribute", attrName, "value", value)
					continue
				}
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
	if saltPlainTypes[attrType] {
		// decrypted, then decoded as attrType; other methods aren't, don't present ciphertext as the type
		if f.encrypt == encryptTunnelPassword && !f.hasTag {
			return saltTypePrefix + attrType
		}
		return typeOctets
	}
	if attrType != typeString && attrType != typeOctets {
		return attrType
	}
	switch f.encrypt {
	case encryptUserPassword:
		return typePassword
	case encryptTunnelPassword:
		if f.hasTag {
			return typeTunnelPassword
		}
		// RFC 2548: no tag byte
		if attrType == typeOctets {
			return typeSaltOctets
		}
		return typeSaltString
	case encryptAscendSecret:
		// Not decrypted yet; don't present ciphertext as text.
		return typeOctets
	}
	// unknown method, warned about in parseAttributeFlags
	return typeOctets
}

func (d *Dictionary) parseAttribute(attrName string, attrID string, attrType string, flags string) error {
	if len(d.tlvStack) > 0 || strings.Contains(attrID, ".") {
		return d.parseTLVAttribute(attrName, attrID, attrType, flags)
	}
	if d.evsBlock != nil {
		num, err := strconv.ParseUint(attrID, 0, 8)
		if err != nil {
			logger().Warn("radius: ignoring attribute with invalid id", "attribute", attrName, "id", attrID, "error", err)
			return nil
		}
		return d.parseExtAttribute(attrName, d.evsBlock.id.Type, uint8(num), attrType, flags)
	}

	// 0 - guess base (0x for hex)
	aID, err := strconv.ParseUint(attrID, 0, 8*int(d.formatOf(d.currentVendor).TypeLen))
	if err != nil {
		logger().Warn("radius: ignoring attribute with invalid id", "attribute", attrName, "id", attrID, "error", err)
		// ignore errors
		return nil
	}

	if v3, ok := v4TypeAliases[attrType]; ok {
		attrType = v3
	}
	f := parseAttributeFlags(attrName, flags)
	attrType = f.effectiveType(attrType)

	if old := d.tlvAttrs[d.currentVendor][attrName]; old != nil && old.parent != nil {
		return fmt.Errorf("duplicate attribute %s, already a sub-attribute of %s", attrName, old.parent.name)
	}
	if _, ok := d.extAttrs[d.currentVendor][attrName]; ok {
		return fmt.Errorf("duplicate attribute %s, already an extended attribute", attrName)
	}
	if id, oldType, ok := d.topLevelDef(attrName); ok {
		if id != uint32(aID) || wireType(oldType) != wireType(attrType) || encryptMethod(oldType, d.topLevelFlags(attrName)) != encryptMethod(attrType, f) {
			return fmt.Errorf("duplicate attribute %s with another definition", attrName)
		}
		// an equivalent redeclaration keeps the first definition, sub-attributes and VALUEs,
		// and decodes the number again
		if d.currentVendor > 0 {
			d.vsaAttrName[d.currentVendor][VendorAttr(aID)] = attrName
		} else {
			d.attrName[AttributeType(aID)] = attrName
		}
		return nil
	}
	// another name for a number is an alias: both encode, the last one decodes
	if attrType == typeTLV && d.formatOf(d.currentVendor).tlvSupported() {
		if t := d.aliasedTLV(0, uint8(aID)); t != nil {
			// a TLV alias shares the sub-attributes, and the first one's encrypt=
			warnUnbuildableTLV(&tlvAttr{name: attrName, attrType: attrType, encrypt: f.encrypt})
			d.addTLVAttr(t, attrName)
		} else {
			t := &tlvAttr{name: attrName, num: uint8(aID), attrType: attrType, encrypt: f.encrypt}
			warnUnbuildableTLV(t)
			d.addTLVAttr(t, attrName)
		}
	}

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

// parseTLVAttribute adds a sub-attribute declared with a dotted OID or inside BEGIN-TLV.
func (d *Dictionary) parseTLVAttribute(attrName string, attrID string, attrType string, flags string) error {
	if len(d.tlvStack) == 0 && d.evsBlock == nil && d.currentVendor == 0 && dottedEVS(attrID) {
		d.skipAttr(attrName)
		logger().Debug("radius: ignoring unsupported sub-attribute", "attribute", attrName, "id", attrID)
		return nil
	}
	oid, err := parseOID(attrID)
	if err != nil {
		logger().Warn("radius: ignoring attribute with invalid id", "attribute", attrName, "id", attrID, "error", err)
		return nil
	}
	var outer AttributeType
	if len(d.tlvStack) == 0 {
		if d.evsBlock != nil {
			outer = d.evsBlock.id.Type
		} else if _, ok := d.extendedParent(oid[0]); ok {
			outer, oid = AttributeType(oid[0]), oid[1:]
			if len(oid) == 1 {
				return d.parseExtAttribute(attrName, outer, oid[0], attrType, flags)
			}
		}
	}
	parent, status := d.tlvParent(outer, oid)
	switch status {
	case tlvParentUnknown:
		d.skipAttr(attrName)
		logger().Warn("radius: ignoring sub-attribute of unknown attribute", "attribute", attrName, "id", attrID)
		return nil
	case tlvParentNotTLV:
		d.skipAttr(attrName)
		logger().Warn("radius: ignoring sub-attribute, parent is not a TLV", "attribute", attrName, "id", attrID)
		return nil
	case tlvParentUnsupported:
		// Extended-Vendor-Specific, non-default vendor formats (WiMAX)
		d.skipAttr(attrName)
		logger().Debug("radius: ignoring unsupported sub-attribute", "attribute", attrName, "id", attrID)
		return nil
	}

	if v3, ok := v4TypeAliases[attrType]; ok {
		attrType = v3
	}
	f := parseAttributeFlags(attrName, flags)
	if f.hasTag {
		logger().Warn("radius: ignoring has_tag of sub-attribute", "attribute", attrName)
	}
	num := oid[len(oid)-1]
	if old := d.tlvAttrs[d.currentVendor][attrName]; old != nil {
		if old.parent != parent || old.num != num || old.attrType != attrType || old.encrypt != f.encrypt {
			return fmt.Errorf("duplicate attribute %s with another definition", attrName)
		}
		// an identical redeclaration
		return nil
	}
	if _, _, ok := d.topLevelDef(attrName); ok {
		return fmt.Errorf("duplicate attribute %s, already a top-level attribute", attrName)
	}
	if _, ok := d.extAttrs[d.currentVendor][attrName]; ok {
		return fmt.Errorf("duplicate attribute %s, already an extended attribute", attrName)
	}
	child := &tlvAttr{name: attrName, num: num, attrType: attrType, encrypt: f.encrypt}
	if !parent.addChild(child) {
		d.skipAttr(attrName)
		return nil
	}
	warnUnbuildableTLV(child)
	d.addTLVAttr(child, child.name)
	return nil
}

// warnUnbuildableTLV warns if t's encrypt= isn't supported: encrypt=1 on a non-string
// (decrypting strips trailing zeros), an encrypted TLV, encrypt=3; such values can't be built or decrypted.
func warnUnbuildableTLV(t *tlvAttr) {
	if t.encrypt != encryptNone && !t.canEncrypt() {
		logger().Warn("radius: encryption of TLV attribute not supported", "attribute", t.name, "type", t.attrType, "encrypt", t.encrypt)
	}
}

// dottedEVS reports whether attrID is an Extended-Vendor-Specific id like 241.26.11344.1, whose vendor may not fit a byte.
func dottedEVS(attrID string) bool {
	parts := strings.SplitN(attrID, ".", 3)
	if len(parts) < 3 || parts[1] != strconv.Itoa(ExtTypeEVS) {
		return false
	}
	outer, err := strconv.ParseUint(parts[0], 0, 8)
	return err == nil && isExtendedType(AttributeType(outer))
}

// parseOID parses a dotted attribute number such as "59.1".
func parseOID(attrID string) ([]uint8, error) {
	var oid []uint8
	for _, s := range strings.Split(attrID, ".") {
		n, err := strconv.ParseUint(s, 0, 8)
		if err != nil {
			return nil, err
		}
		oid = append(oid, uint8(n))
	}
	return oid, nil
}

type tlvParentStatus int

const (
	tlvParentOK          tlvParentStatus = iota
	tlvParentUnknown                     // parent isn't defined
	tlvParentNotTLV                      // parent is a plain attribute
	tlvParentUnsupported                 // EVS, extended VSA, non-default vendor format, ignored block
)

// extendedTypes are RFC 6929 attribute types; sub-attributes are supported only for standard ones.
var extendedTypes = map[string]bool{typeExtended: true, typeLongExtended: true, typeEVS: true}

// tlvParent returns the TLV holding the last component of oid; outer is the extended attribute oid is under, or 0.
func (d *Dictionary) tlvParent(outer AttributeType, oid []uint8) (*tlvAttr, tlvParentStatus) {
	var parent *tlvAttr
	if n := len(d.tlvStack); n > 0 {
		if parent = d.tlvStack[n-1].attr; parent == nil {
			return nil, tlvParentUnsupported
		}
	} else {
		var name, attrType string
		var ok bool
		switch {
		case outer != 0:
			var e *extAttr
			if e, ok = d.extNums[d.currentVendor][extKey{outer: outer, num: oid[0]}]; ok {
				name, attrType = e.name, e.attrType
			}
		case d.currentVendor > 0:
			name, ok = d.vsaAttrName[d.currentVendor][VendorAttr(oid[0])]
			attrType = d.vsaAttrType[d.currentVendor][name]
		default:
			name, ok = d.attrName[AttributeType(oid[0])]
			attrType = d.attrType[name]
		}
		if !ok {
			return nil, tlvParentUnknown
		}
		if parent = d.rootTLV(d.currentVendor, name); parent == nil {
			if attrType == typeEVS || outer == 0 && (!d.formatOf(d.currentVendor).tlvSupported() || extendedTypes[attrType]) {
				return nil, tlvParentUnsupported
			}
			return nil, tlvParentNotTLV
		}
		oid = oid[1:]
	}
	for _, n := range oid[:len(oid)-1] {
		if parent.attrType != typeTLV {
			return nil, tlvParentNotTLV
		}
		child, ok := parent.children[n]
		if !ok {
			// e.g. 241.26.x under an ignored Extended-Vendor-Specific
			return nil, tlvParentUnknown
		}
		parent = child
	}
	if parent.attrType != typeTLV {
		return nil, tlvParentNotTLV
	}
	return parent, tlvParentOK
}

// topLevelDef returns the number and type of top-level attribute attrName of the current vendor.
func (d *Dictionary) topLevelDef(attrName string) (uint32, string, bool) {
	if d.currentVendor > 0 {
		id, ok := d.vsaAttrID[d.currentVendor][attrName]
		return uint32(id), d.vsaAttrType[d.currentVendor][attrName], ok
	}
	id, ok := d.attrID[attrName]
	return uint32(id), d.attrType[attrName], ok
}

// encryptMethod returns the encrypt= method of attrType with flags f, counting the builtin password types.
func encryptMethod(attrType string, f attributeFlags) int {
	switch {
	case f.encrypt != encryptNone:
		return f.encrypt
	case attrType == typePassword:
		return encryptUserPassword
	case attrType == typeTunnelPassword, strings.HasPrefix(attrType, saltTypePrefix):
		return encryptTunnelPassword
	}
	return encryptNone
}

// topLevelFlags returns the flags of top-level attribute attrName of the current vendor.
func (d *Dictionary) topLevelFlags(attrName string) attributeFlags {
	if d.currentVendor > 0 {
		return d.vsaAttrFlags[d.currentVendor][attrName]
	}
	return d.attrFlags[attrName]
}

// formatOf returns the VSA format of vendor; caller holds the lock.
func (d *Dictionary) formatOf(vendor VendorID) VendorFormat {
	if f, ok := d.vendorFormat[vendor]; ok {
		return f
	}
	return DefaultVendorFormat
}

// rawVSAString formats a VSA of an unknown attribute, naming the vendor if known.
func rawVSAString(vsa *VSA, vendorName string, vendorOK bool) string {
	// as AvpVendor without a dictionary
	vendor := " " + strconv.FormatUint(uint64(vsa.Vendor), 10)
	if vendorOK {
		vendor = vendorName + " #" + vendor[1:]
	}
	return fmt.Sprintf("{Vendor:%s, Attr: %d, Value: %#v}", vendor, vsa.Type, vsa.Value)
}

// wireTypes maps types to a type with the same encoding, e.g. builtin vs FreeRADIUS definitions.
var wireTypes = map[string]string{
	typeEAPMessage: typeOctets,
	typeSaltString: typeSaltOctets,
}

// wireType returns the type attrType is encoded as, for comparing redeclarations.
func wireType(attrType string) string {
	if t, ok := wireTypes[attrType]; ok {
		return t
	}
	return attrType
}

// skipAttr records an ignored sub-attribute of the current vendor; its VALUEs are skipped quietly.
func (d *Dictionary) skipAttr(attrName string) {
	if _, ok := d.skippedAttrs[d.currentVendor]; !ok {
		d.skippedAttrs[d.currentVendor] = make(map[string]bool)
	}
	d.skippedAttrs[d.currentVendor][attrName] = true
}

// addTLVAttr indexes t as name under the current vendor.
func (d *Dictionary) addTLVAttr(t *tlvAttr, name string) {
	if _, ok := d.tlvAttrs[d.currentVendor]; !ok {
		d.tlvAttrs[d.currentVendor] = make(map[string]*tlvAttr)
	}
	d.tlvAttrs[d.currentVendor][name] = t
}

// aliasedTLV returns the TLV definition of top-level (or extended under outer) attribute number id of the current vendor, or nil.
func (d *Dictionary) aliasedTLV(outer AttributeType, id uint8) *tlvAttr {
	// the last name for id may be a non-TLV alias
	for _, t := range d.tlvAttrs[d.currentVendor] {
		if t.parent == nil && t.outer == outer && t.num == id {
			return t
		}
	}
	return nil
}

func (d *Dictionary) parseValue(attrName string, constName string, constValue string) error {
	if t := d.tlvAttrs[d.currentVendor][attrName]; t != nil && t.parent != nil {
		cID, err := parseInteger(attrTypeHandlers[t.attrType], constValue)
		if err != nil {
			return fmt.Errorf("value %s of attribute %s: %w", constName, attrName, err)
		}
		t.addValue(constName, cID)
		return nil
	}
	if e := d.extAttrs[d.currentVendor][attrName]; e != nil {
		cID, err := parseInteger(attrTypeHandlers[e.attrType], constValue)
		if err != nil {
			return fmt.Errorf("value %s of attribute %s: %w", constName, attrName, err)
		}
		e.addValue(constName, cID)
		return nil
	}

	var present bool
	var attrType string
	if d.currentVendor > 0 {
		_, present = d.vsaAttrID[d.currentVendor][attrName]
		attrType = d.vsaAttrType[d.currentVendor][attrName]
	} else {
		_, present = d.attrID[attrName]
		attrType = d.attrType[attrName]
	}

	if !present {
		if d.skippedAttrs[d.currentVendor][attrName] {
			logger().Debug("radius: ignoring value for unsupported sub-attribute", "attribute", attrName, "value", constName)
			return nil
		}
		logger().Warn("radius: ignoring value for unknown attribute", "attribute", attrName, "value", constName)
		// ignore 'compat' errors
		return nil
	}

	// some values defined as 0x.. - using '0' to auto-detect
	cID, err := parseInteger(attrTypeHandlers[attrType], constValue)
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

		d.vsaConstID[d.currentVendor][attrName][constName] = cID
		d.vsaConstName[d.currentVendor][attrName][cID] = constName
	} else {
		if _, exist := d.constID[attrName]; !exist {
			d.constID[attrName] = make(map[string]uint32)
			d.constName[attrName] = make(map[uint32]string)
		}

		d.constID[attrName][constName] = cID
		d.constName[attrName][cID] = constName
	}

	return nil
}

var blacklistDictionary = map[string]int{
	"dictionary.freeradius.internal": 1,
	"dictionary.compat":              1,
	"dictionary.usr.illegal":         1,
	"dictionary.vqp":                 1,
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
	if err := d.checkNoTLVBlock("$INCLUDE " + incName); err != nil {
		return err
	}
	// clear vendor
	d.currentVendor = 0
	d.evsBlock = nil
	return d.loadFileInternal(fullName)
}

func (d *Dictionary) parseVendor(vendorName string, vendorID string, format string) error {
	vID, err := strconv.ParseUint(vendorID, 0, 32)
	if err != nil {
		return fmt.Errorf("vendor %s: %w", vendorName, err)
	}
	f, err := parseVendorFormat(format)
	if err != nil {
		return fmt.Errorf("vendor %s: %w", vendorName, err)
	}
	if f != DefaultVendorFormat {
		d.vendorFormat[VendorID(vID)] = f
	} else {
		delete(d.vendorFormat, VendorID(vID))
	}

	d.vendorID[vendorName] = VendorID(vID)
	d.vendorName[VendorID(vID)] = vendorName

	return nil
}

// parseVendorFormat parses a VENDOR "format=T,L[,c]" argument; "" is format=1,1.
func parseVendorFormat(format string) (VendorFormat, error) {
	if format == "" {
		return DefaultVendorFormat, nil
	}
	spec, ok := strings.CutPrefix(format, "format=")
	parts := strings.Split(spec, ",")
	if !ok || len(parts) < 2 || len(parts) > 3 {
		return VendorFormat{}, fmt.Errorf("invalid VENDOR option %s", format)
	}
	t, errT := strconv.ParseUint(parts[0], 10, 8)
	l, errL := strconv.ParseUint(parts[1], 10, 8)
	f := VendorFormat{TypeLen: uint8(t), LengthLen: uint8(l)}
	if len(parts) == 3 {
		f.Continuation = parts[2] == "c"
	}
	if errT != nil || errL != nil || f.TypeLen == 0 || len(parts) == 3 && !f.Continuation || !f.Valid() {
		return VendorFormat{}, fmt.Errorf("invalid %s", format)
	}
	return f, nil
}

func (d *Dictionary) parseBeginVendor(vendorName string, option string) error {
	if err := d.checkNoTLVBlock("BEGIN-VENDOR " + vendorName); err != nil {
		return err
	}
	vID, ok := d.vendorID[vendorName]
	if !ok {
		return errors.New("unknown vendor " + vendorName)
	}
	if err := d.parseBeginVendorFormat(vendorName, option); err != nil {
		return err
	}
	d.currentVendor = vID
	return nil
}

func (d *Dictionary) parseEndVendor(vendorName string) error {
	if err := d.checkNoTLVBlock("END-VENDOR " + vendorName); err != nil {
		return err
	}
	vID, ok := d.vendorID[vendorName]
	if !ok {
		return errors.New("unknown vendor " + vendorName)
	}

	if d.currentVendor == 0 || d.currentVendor != vID {
		return errors.New("unexpected END-VENDOR found")
	}

	d.currentVendor = 0
	d.evsBlock = nil

	return nil
}

// checkNoTLVBlock returns an error if a BEGIN-TLV block is open at line.
func (d *Dictionary) checkNoTLVBlock(line string) error {
	if n := len(d.tlvStack); n > 0 {
		return fmt.Errorf("%s inside BEGIN-TLV %s", line, d.tlvStack[n-1].name)
	}
	return nil
}

func (d *Dictionary) parseBeginTLV(attrName string) error {
	t := d.tlvAttrs[d.currentVendor][attrName]
	_, vsa := d.vsaAttrID[d.currentVendor][attrName]
	_, std := d.attrID[attrName]
	_, ext := d.extAttrs[d.currentVendor][attrName]
	known := vsa || ext || (d.currentVendor == 0 && std)
	switch {
	case t != nil && t.attrType != typeTLV:
		return errors.New("Not a TLV attribute " + attrName)
	case t != nil:
		// a known TLV: open its block
	case d.skippedAttrs[d.currentVendor][attrName] || (known && !d.formatOf(d.currentVendor).tlvSupported()):
		logger().Debug("radius: ignoring TLV sub-attributes", "attribute", attrName)
	case known:
		return errors.New("Not a TLV attribute " + attrName)
	default:
		return errors.New("Unknown TLV attribute " + attrName)
	}
	d.tlvStack = append(d.tlvStack, tlvBlock{name: attrName, attr: t})
	return nil
}

func (d *Dictionary) parseEndTLV(attrName string) error {
	n := len(d.tlvStack)
	if n == 0 || d.tlvStack[n-1].name != attrName {
		return fmt.Errorf("unexpected END-TLV %s", attrName)
	}
	d.tlvStack = d.tlvStack[:n-1]
	return nil
}

// dictionary attribute type names
const (
	typeInteger        = "integer"
	typeByte           = "byte"
	typeShort          = "short"
	typeSigned         = "signed"
	typeIPAddr         = "ipaddr"
	typeIPv6Addr       = "ipv6addr"
	typeIPv6Prefix     = "ipv6prefix"
	typeIfid           = "ifid"
	typeEther          = "ether"
	typeDate           = "date"
	typeComboIP        = "combo-ip"
	typeString         = "string"
	typeOctets         = "octets"
	typePassword       = "password"
	typeTunnelPassword = "tunnel-password"
	typeSaltString     = saltTypePrefix + typeString
	typeSaltOctets     = saltTypePrefix + typeOctets
	typeTaggedInteger  = "tagged-integer"
	typeTaggedString   = "tagged-string"
	typeVSA            = "vsa"
	typeEAPMessage     = "eapmessage"
)

// saltTypePrefix names untagged encrypt=2 types (RFC 2548), e.g. salt-encrypted-integer.
const saltTypePrefix = "salt-encrypted-"

// saltPlainTypes are the non-string types an untagged encrypt=2 value decrypts to.
var saltPlainTypes = map[string]bool{
	typeInteger: true, typeByte: true, typeShort: true, typeSigned: true,
	typeIPAddr: true, typeIPv6Addr: true, typeIPv6Prefix: true,
	typeIfid: true, typeEther: true, typeDate: true, typeComboIP: true,
}

func init() {
	for t := range saltPlainTypes {
		attrTypeHandlers[saltTypePrefix+t] = AvpSaltEncrypted{plain: attrTypeHandlers[t]}
	}
}

// attribute type to handler mapping
var attrTypeHandlers = map[string]avpDataType{
	typeInteger:        avpUint32,
	typeByte:           avpUint8,
	typeShort:          avpUint16,
	typeSigned:         avpInt32,
	typeIPAddr:         avpIP,
	typeIPv6Addr:       avpIPv6,
	typeIPv6Prefix:     avpIPv6Prefix,
	typeString:         avpString,
	typeOctets:         avpBinary,
	typePassword:       avpPassword,
	typeTunnelPassword: avpTunnelPassword,
	typeSaltString:     avpSaltString,
	typeSaltOctets:     avpSaltOctets,
	typeTaggedInteger:  avpTaggedUint32,
	typeTaggedString:   avpTaggedString,
	typeVSA:            avpVendor,
	typeEAPMessage:     avpEapMessage,
	typeIfid:           avpIfid,
	typeEther:          avpEther,
	typeDate:           avpDate,
	typeComboIP:        avpComboIP,
	// "abinary"
}

// handlerForValue returns the handler for attrType, or avpBinary if value is malformed for it.
func handlerForValue(attrType string, value []byte) avpDataType {
	handler := attrTypeHandlers[attrType]
	if handler == nil || !validValue(handler, value) {
		return avpBinary
	}
	return handler
}

// validValue reports whether value fits handler; "integer" keeps accepting trailing bytes.
func validValue(handler avpDataType, value []byte) bool {
	n := len(value)
	switch handler {
	case avpUint32, avpTaggedUint32:
		return n >= uint32Size
	case avpUint8:
		return n == uint8Size
	case avpUint16:
		return n == uint16Size
	case avpInt32:
		return n == int32Size
	case avpIPv6Prefix:
		_, ok := decodeIPv6Prefix(value)
		return ok
	case avpIfid:
		return n == ifidLen
	case avpEther:
		return n == etherLen
	case avpDate:
		return n == dateLen
	case avpComboIP:
		return n == net.IPv4len || n == net.IPv6len
	}
	return true
}

// DecodeAVPValue returns a human-readable string for the given AVP.
//
// When possible, DecodeAVPValue uses dictionary type information and enum
// mappings (including VSA enums) to format values.
func (d *Dictionary) DecodeAVPValue(p *Packet, a AVP) string {
	if a.Type == AttrUserPassword {
		return avpPassword.String(p, a)
	} else if a.Type == AttrVendorSpecific {
		vendor, _ := vsaVendor(a.Value)
		d.mu.RLock()
		vsa, ok := decodeVSA(a, d.formatOf(vendor))
		if !ok {
			d.mu.RUnlock()
			return avpBinary.String(p, a)
		}
		vendorName, vendorOK := d.vendorName[vsa.Vendor]
		attrName, attrOK := d.vsaAttrName[vsa.Vendor][vsa.Type]
		if !attrOK {
			d.mu.RUnlock()
			return rawVSAString(vsa, vendorName, vendorOK)
		}
		if t := d.rootTLV(vsa.Vendor, attrName); t != nil {
			valStr := t.format(p, vsa.Value)
			d.mu.RUnlock()
			return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
				vendorName, vsa.Vendor, attrName, vsa.Type, valStr)
		}
		handler, v := plainValue(p, d.vsaAttrType[vsa.Vendor][attrName], vsa.Value)
		// Try to lookup enum name for VSAs too
		valStr, ok := enumName(handler, v, d.vsaConstName[vsa.Vendor][attrName])
		d.mu.RUnlock()
		if !ok {
			valStr = handler.String(p, AVP{Value: v})
		}

		return fmt.Sprintf("{Vendor:%s #%d, Attr: %s #%d, Value: %s}",
			vendorName, vsa.Vendor, attrName, vsa.Type, valStr)

	}

	d.mu.RLock()
	attrName := d.attrName[a.Type]
	switch d.attrType[attrName] {
	case typeExtended, typeLongExtended:
		s := d.formatExtended(p, a, d.attrType[attrName] == typeLongExtended)
		d.mu.RUnlock()
		return s
	}
	if t := d.rootTLV(0, attrName); t != nil {
		s := t.format(p, a.Value)
		d.mu.RUnlock()
		return s
	}
	handler, v := plainValue(p, d.attrType[attrName], a.Value)
	// Try to lookup enum name for standard attributes
	name, ok := enumName(handler, v, d.constName[attrName])
	d.mu.RUnlock()
	if ok {
		return name
	}

	return handler.String(p, AVP{Type: a.Type, Value: v})
}

// plainValue returns the handler for value of attrType and the value, decrypted with p if it is salt-encrypted;
// ciphertext that can't be decrypted is octets.
func plainValue(p *Packet, attrType string, value []byte) (avpDataType, []byte) {
	handler := handlerForValue(attrType, value)
	s, ok := handler.(AvpSaltEncrypted)
	if !ok || p.masks() {
		// AvpSaltEncrypted.String masks it
		return handler, value
	}
	plain, ok := s.decrypt(p, value)
	if !ok || !validValue(s.plain, plain) {
		return avpBinary, value
	}
	return s.plain, plain
}

// enumName returns the VALUE name of an integer value, with its tag if any; caller holds the lock.
func enumName(handler avpDataType, value []byte, names map[uint32]string) (string, bool) {
	var v uint32
	switch handler {
	case avpUint32, avpTaggedUint32, avpUint8, avpUint16:
		v = handler.Value(nil, AVP{Value: value}).(uint32)
	case avpInt32:
		v = uint32(handler.Value(nil, AVP{Value: value}).(int32))
	default:
		return "", false
	}
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

// VendorFormat returns the VSA format of a vendor, DefaultVendorFormat if it has none or is unknown.
func (d *Dictionary) VendorFormat(vendorID VendorID) VendorFormat {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.formatOf(vendorID)
}

// GetVSA returns a copy of the first value of vendor attribute attrName in p,
// joining values split with the WiMAX continuation byte. Encrypted values are decrypted
// (without the tag); malformed ciphertext is not found, a wrong secret gives garbage.
func (d *Dictionary) GetVSA(p *Packet, vendorName, attrName string) ([]byte, bool) {
	d.mu.RLock()
	vendorID, vendorOK := d.vendorID[vendorName]
	attrID, attrOK := d.vsaAttrID[vendorID][attrName]
	handler := attrTypeHandlers[d.vsaAttrType[vendorID][attrName]]
	f := d.formatOf(vendorID)
	d.mu.RUnlock()
	if !vendorOK || !attrOK {
		return nil, false
	}
	var found []byte
	ok := false
	eachVSA(p, vendorID, f, func(typ VendorAttr, v []byte) bool {
		if typ == attrID {
			found, ok = bytes.Clone(v), true
		}
		return !ok
	})
	if !ok {
		return nil, false
	}
	return decryptHandlerValue(p, handler, found)
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
// Extended attributes (RFC 6929) are accepted if the value fits one AVP; see ParseExtended.
func (d *Dictionary) ParseAVP(attrName string, attrValue string) (AVP, error) {
	attrName, tag, tagged, err := splitTagName(attrName)
	if err != nil {
		return AVP{}, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	attrID, ok := d.attrID[attrName]
	if e := d.extAttrs[0][attrName]; !ok && e != nil {
		return parseExtendedAVP(e, attrName, tagged, attrValue)
	}
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
		return AVP{}, fmt.Errorf("%w%s for attribute %s", err, encryptedHint(err, attrID), attrName)
	}
	return AVP{Type: attrID, Value: value}, nil
}

// ParseVSA constructs a Vendor-Specific Attribute from the vendor name, attribute
// name, and a string value using the VSA type defined in the dictionary.
// An encrypted attribute keeps the plaintext and is encrypted by Packet.AddVSA.
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
	vsa := VSA{Vendor: vendorID, Type: attrID, Format: d.formatOf(vendorID)}
	if isEncrypted(handler) {
		// Packet.AddVSA encrypts it
		plain, err := hiddenValue(handler, d.vsaConstID[vendorID][attrName], attrValue)
		if err != nil {
			return VSA{}, fmt.Errorf("%w for attribute %s/%s", err, vendorName, attrName)
		}
		vsa.Value, vsa.enc, vsa.tag = []byte(plain), handler, tag
	} else {
		value, err := encodeValue(handler, d.vsaConstID[vendorID][attrName], tag, attrValue)
		if err != nil {
			return VSA{}, fmt.Errorf("%w for attribute %s/%s", err, vendorName, attrName)
		}
		vsa.Value = value
	}
	if err := vsa.check(); err != nil {
		return VSA{}, fmt.Errorf("%w for attribute %s/%s", err, vendorName, attrName)
	}
	return vsa, nil
}

// encryptedHint names the Packet method that builds encrypted attribute id, if there is one.
func encryptedHint(err error, id AttributeType) string {
	if !errors.Is(err, ErrEncryptedAttribute) {
		return ""
	}
	switch id {
	case AttrUserPassword:
		return ", use AddPassword"
	case AttrTunnelPassword:
		return ", use AddTunnelPassword"
	}
	return ""
}

// encodeValue encodes value with handler; integers accept a VALUE name from names or a number.
func encodeValue(handler avpDataType, names map[string]uint32, tag uint8, value string) ([]byte, error) {
	if isEncrypted(handler) {
		return nil, ErrEncryptedAttribute
	}
	switch handler {
	case avpTaggedString:
		return encodeTaggedString(tag, value), nil
	case avpUint32, avpTaggedUint32, avpUint8, avpUint16, avpInt32:
		return encodeInteger(handler, names, tag, value)
	case avpIP:
		// AvpIP.FromString also parses IPv6
		if b := handler.FromString(value); len(b) == net.IPv4len {
			return b, nil
		}
		return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
	case avpIPv6, avpIPv6Prefix, avpIfid, avpEther, avpDate, avpComboIP:
		if b := handler.FromString(value); b != nil {
			return b, nil
		}
		return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
	}
	return handler.FromString(value), nil
}

// encodeInteger encodes a VALUE name from names or a number, range-checked for handler.
func encodeInteger(handler avpDataType, names map[string]uint32, tag uint8, value string) ([]byte, error) {
	v, known := names[value]
	if !known {
		n, err := parseInteger(handler, value)
		if err != nil {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		v = n
	}
	switch handler {
	case avpUint8:
		if v > math.MaxUint8 {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		return []byte{uint8(v)}, nil
	case avpUint16:
		if v > math.MaxUint16 {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		return binary.BigEndian.AppendUint16(nil, uint16(v)), nil
	case avpTaggedUint32:
		if v > taggedIntMax {
			return nil, fmt.Errorf("%w %q", ErrInvalidValue, value)
		}
		v |= uint32(tag) << 24
	}
	return encodeUint32(v), nil
}

// parseInteger parses a 32-bit number; "signed" accepts negatives, stored as two's complement.
func parseInteger(handler avpDataType, value string) (uint32, error) {
	if s, ok := handler.(AvpSaltEncrypted); ok {
		handler = s.plain
	}
	if handler == avpInt32 {
		n, err := strconv.ParseInt(value, 0, 32)
		return uint32(n), err
	}
	n, err := strconv.ParseUint(value, 0, 32)
	return uint32(n), err
}
