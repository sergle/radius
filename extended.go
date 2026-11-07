package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// dictionary types of RFC 6929 attributes
const (
	typeExtended     = "extended"
	typeLongExtended = "long-extended"
	typeEVS          = "evs"
)

const (
	// ExtTypeEVS is the Extended-Type of Extended-Vendor-Specific attributes (RFC 6929 §2.4).
	ExtTypeEVS = 26

	extHeaderLen     = 1               // Extended-Type
	longExtHeaderLen = 2               // Extended-Type + flags
	evsHeaderLen     = vendorIDLen + 1 // Vendor-Id + Vendor-Type
	extMoreFlag      = 0x80            // Long Extended Type: the value continues in the next attribute
	maxLongExtData   = maxAVPValueLen - longExtHeaderLen
	maxEVSVendor     = 1<<24 - 1 // Vendor-Id high octet is zero (RFC 6929 §2.4)
)

// ExtendedAttr is an RFC 6929 extended attribute (types 241-246).
//
// With ExtType ExtTypeEVS it is an Extended-Vendor-Specific attribute of Vendor
// and VendorType. Types 245 and 246 use the Long Extended Type format, whose
// values may span several AVPs.
type ExtendedAttr struct {
	Type       AttributeType
	ExtType    uint8
	Vendor     VendorID
	VendorType uint8
	Value      []byte
}

// extAttr is a dictionary definition of an extended or Extended-Vendor-Specific attribute.
type extAttr struct {
	name      string
	key       extKey
	id        ExtendedAttr // without Value
	attrType  string
	encrypt   int // encrypt= method (encryptMethod); can't be built, it would be sent unencrypted
	constID   map[string]uint32
	constName map[uint32]string
}

// extKey is an extended attribute number: the Extended-Type, or the Vendor-Type of an EVS attribute.
type extKey struct {
	outer AttributeType
	num   uint8
}

// addValue records a VALUE name for e.
func (e *extAttr) addValue(name string, v uint32) {
	if e.constID == nil {
		e.constID = make(map[string]uint32)
		e.constName = make(map[uint32]string)
	}
	e.constID[name] = v
	e.constName[v] = name
}

// payload returns the data after the Extended-Type (and flags) header.
func (e ExtendedAttr) payload() []byte {
	if e.ExtType != ExtTypeEVS {
		return e.Value
	}
	b := make([]byte, 0, evsHeaderLen+len(e.Value))
	b = binary.BigEndian.AppendUint32(b, uint32(e.Vendor))
	b = append(b, e.VendorType)
	return append(b, e.Value...)
}

// isExtendedType reports whether t is an RFC 6929 extended attribute type (241-246).
func isExtendedType(t AttributeType) bool {
	return t >= AttrExtendedType1 && t <= AttrLongExtendedType2
}

// long reports whether e uses the Long Extended Type format (245, 246).
func (e ExtendedAttr) long() bool {
	return e.Type == AttrLongExtendedType1 || e.Type == AttrLongExtendedType2
}

// check reports an error if e can't be encoded: another type, an empty value, a bad Vendor-Id,
// or a value too long for one AVP of a type without the Long format.
func (e ExtendedAttr) check() error {
	switch {
	case !isExtendedType(e.Type):
		return fmt.Errorf("%w: type %d is not an extended attribute", ErrInvalidValue, e.Type)
	case len(e.Value) == 0:
		return fmt.Errorf("%w: empty value", ErrInvalidValue)
	case e.ExtType == ExtTypeEVS && e.Vendor > maxEVSVendor:
		return fmt.Errorf("%w: Vendor-Id %d", ErrInvalidValue, e.Vendor)
	case !e.long() && extHeaderLen+len(e.payload()) > maxAVPValueLen:
		return fmt.Errorf("%w: value too long", ErrInvalidValue)
	}
	return nil
}

// ToAVPList encodes e; a long value of the Long format is split over several AVPs with the More flag.
// A value that can't be encoded (see check) is logged and gives nil.
func (e ExtendedAttr) ToAVPList() []AVP {
	if err := e.check(); err != nil {
		logger().Warn("radius: ExtendedAttr.ToAVPList", "type", e.Type, "ext", e.ExtType, "error", err)
		return nil
	}
	data := e.payload()
	if !e.long() {
		return []AVP{{Type: e.Type, Value: append([]byte{e.ExtType}, data...)}}
	}
	var avps []AVP
	for {
		n := min(len(data), maxLongExtData)
		flags := byte(0)
		if n < len(data) {
			flags = extMoreFlag
		}
		value := append([]byte{e.ExtType, flags}, data[:n]...)
		avps = append(avps, AVP{Type: e.Type, Value: value})
		if data = data[n:]; len(data) == 0 {
			return avps
		}
	}
}

// AddExtended adds an extended attribute to the packet, split over several if needed (Long format).
func (p *Packet) AddExtended(e ExtendedAttr) {
	p.AddAVP(e.ToAVPList()...)
}

// splitExtended returns the Extended-Type, More flag and data of an extended AVP value; data can't be empty.
func splitExtended(value []byte, long bool) (ext uint8, more bool, data []byte, ok bool) {
	hdr := extHeaderLen
	if long {
		hdr = longExtHeaderLen
	}
	if len(value) <= hdr {
		return 0, false, nil, false
	}
	if long {
		more = value[1]&extMoreFlag != 0
	}
	return value[0], more, value[hdr:], true
}

// splitEVS returns the vendor, vendor type and non-empty value of Extended-Vendor-Specific data.
func splitEVS(data []byte) (VendorID, uint8, []byte, bool) {
	if len(data) <= evsHeaderLen || data[0] != 0 {
		return 0, 0, nil, false
	}
	return VendorID(binary.BigEndian.Uint32(data)), data[vendorIDLen], data[evsHeaderLen:], true
}

// match returns the value of extended data of type ext if it is attribute id.
func (id ExtendedAttr) match(ext uint8, data []byte) ([]byte, bool) {
	if ext != id.ExtType {
		return nil, false
	}
	if ext != ExtTypeEVS {
		return data, true
	}
	vendor, vendorType, v, ok := splitEVS(data)
	return v, ok && vendor == id.Vendor && vendorType == id.VendorType
}

// eachExtended calls fn with the Extended-Type and data of each outer attribute in p until fn returns false.
// Long values are joined; an incomplete, interrupted or short-fragmented chain is skipped.
func eachExtended(p *Packet, outer AttributeType, long bool, fn func(ext uint8, data []byte) bool) {
	var pending []byte
	var pendingExt uint8
	chained, bad := false, false
	p.EachAVP(func(a AVP) bool {
		if a.Type != outer {
			chained = false
			return true
		}
		ext, more, data, ok := splitExtended(a.Value, long)
		if !ok {
			chained = false
			return true
		}
		if chained && ext != pendingExt {
			chained = false
		}
		if more || chained {
			if !chained {
				pending, pendingExt, chained, bad = nil, ext, true, false
			}
			// RFC 6929 §2.2: only a full-length fragment may have More set
			bad = bad || more && len(data) != maxLongExtData
			pending = append(pending, data...)
			if more {
				return true
			}
			chained = false
			if bad {
				return true
			}
			data = pending
		}
		return fn(ext, data)
	})
}

// eachExtendedValue calls fn with each value of attribute id in p until fn returns false.
func eachExtendedValue(p *Packet, id ExtendedAttr, fn func(v []byte) bool) {
	eachExtended(p, id.Type, id.long(), func(ext uint8, data []byte) bool {
		if v, ok := id.match(ext, data); ok {
			return fn(v)
		}
		return true
	})
}

// extendedParent reports whether standard attribute num is an extended one, and if it is long; caller holds the lock.
func (d *Dictionary) extendedParent(num uint8) (long bool, ok bool) {
	if d.currentVendor > 0 {
		return false, false
	}
	switch d.attrType[d.attrName[AttributeType(num)]] {
	case typeExtended:
		return false, true
	case typeLongExtended:
		return true, true
	}
	return false, false
}

// parseExtAttribute adds an extended attribute, or an EVS attribute of the current vendor inside BEGIN-VENDOR format=.
func (d *Dictionary) parseExtAttribute(attrName string, outer AttributeType, num uint8, attrType string, flags string) error {
	if v3, ok := v4TypeAliases[attrType]; ok {
		attrType = v3
	}
	f := parseAttributeFlags(attrName, flags)
	if f.hasTag {
		logger().Warn("radius: ignoring has_tag of extended attribute", "attribute", attrName)
	}
	evsBlock := d.evsBlock != nil
	if attrType == typeEVS && (evsBlock || num != ExtTypeEVS) || !evsBlock && num == ExtTypeEVS && attrType != typeEVS {
		return fmt.Errorf("attribute %s: Extended-Type %d must be of type evs", attrName, ExtTypeEVS)
	}
	vendor := d.currentVendor
	if old := d.tlvAttrs[vendor][attrName]; old != nil && old.parent != nil {
		return fmt.Errorf("duplicate attribute %s, already a sub-attribute of %s", attrName, old.parent.name)
	}
	if _, _, ok := d.topLevelDef(attrName); ok {
		return fmt.Errorf("duplicate attribute %s, already a top-level attribute", attrName)
	}
	key := extKey{outer: outer, num: num}
	encrypt := encryptMethod(attrType, f)
	if old := d.extAttrs[vendor][attrName]; old != nil {
		if old.key != key || extWireType(old.attrType, old.encrypt) != extWireType(attrType, encrypt) || old.encrypt != encrypt {
			return fmt.Errorf("duplicate attribute %s with another definition", attrName)
		}
		// an equivalent redeclaration keeps the first definition and decodes the number again
		d.extNums[vendor][key] = old
		return nil
	}

	id := ExtendedAttr{Type: outer, ExtType: num}
	if evsBlock {
		id = ExtendedAttr{Type: outer, ExtType: ExtTypeEVS, Vendor: vendor, VendorType: num}
	}
	e := &extAttr{name: attrName, key: key, id: id, attrType: attrType, encrypt: encrypt}
	if attrType == typeTLV {
		if t := d.aliasedTLV(outer, num); t != nil {
			// an alias shares the first one's encrypt=
			warnUnbuildableTLV(&tlvAttr{name: attrName, attrType: attrType, encrypt: f.encrypt})
			d.addTLVAttr(t, attrName)
		} else {
			t := &tlvAttr{name: attrName, num: num, attrType: attrType, outer: outer, encrypt: f.encrypt}
			warnUnbuildableTLV(t)
			d.addTLVAttr(t, attrName)
		}
	}
	if _, ok := d.extAttrs[vendor]; !ok {
		d.extAttrs[vendor] = make(map[string]*extAttr)
		d.extNums[vendor] = make(map[extKey]*extAttr)
	}
	d.extAttrs[vendor][attrName] = e
	// another name for a number is an alias: both encode, the last one decodes
	d.extNums[vendor][key] = e
	return nil
}

// extWireType is wireType after folding encrypt into attrType, as top-level types are;
// extended attributes have no tags, so tunnel-password is untagged.
func extWireType(attrType string, encrypt int) string {
	t := attributeFlags{encrypt: encrypt}.effectiveType(attrType)
	if t == typeTunnelPassword {
		t = typeSaltOctets
	}
	return wireType(t)
}

// parseBeginVendorFormat sets the Extended-Vendor-Specific attribute named by a BEGIN-VENDOR format= option.
func (d *Dictionary) parseBeginVendorFormat(vendorName, option string) error {
	d.evsBlock = nil
	if option == "" {
		return nil
	}
	name, ok := strings.CutPrefix(option, "format=")
	if !ok {
		name, ok = strings.CutPrefix(option, "parent=")
	}
	if !ok {
		return fmt.Errorf("BEGIN-VENDOR %s: invalid option %s", vendorName, option)
	}
	e := d.extAttrs[0][name]
	if e == nil || e.attrType != typeEVS {
		return fmt.Errorf("BEGIN-VENDOR %s: %s is not an attribute of type evs", vendorName, name)
	}
	d.evsBlock = e
	return nil
}

// formatExtended renders an extended attribute, or octets if it is malformed; caller holds the lock.
// A continuation fragment of a long value is named after the first fragment and shown as octets.
func (d *Dictionary) formatExtended(p *Packet, a AVP, long bool) string {
	ext, more, data, ok := splitExtended(a.Value, long)
	if !ok {
		return avpBinary.String(p, a)
	}
	head, continued := data, false
	if long {
		if first, ok := chainStart(p, a); ok {
			head, continued = first, true
		}
	}
	var vendor VendorID
	num := ext
	prefix := ""
	oid := strconv.Itoa(int(a.Type)) + "." + strconv.Itoa(int(ext))
	if ext == ExtTypeEVS {
		var vendorType uint8
		var v []byte
		vendor, vendorType, v, ok = splitEVS(head)
		if !ok {
			return avpBinary.String(p, a)
		}
		if !continued {
			data = v
		}
		num = vendorType
		oid += "." + strconv.FormatUint(uint64(vendor), 10) + "." + strconv.Itoa(int(vendorType))
		if name, known := d.vendorName[vendor]; known {
			prefix = fmt.Sprintf("Vendor:%s #%d, ", name, vendor)
		} else {
			prefix = fmt.Sprintf("Vendor: %d, ", vendor)
		}
	}
	flags := ""
	if continued {
		flags += ", Continued"
	}
	if more {
		flags += ", More"
	}
	var e *extAttr
	// vendor 0 would look up standard attributes
	if ext != ExtTypeEVS || vendor != 0 {
		e = d.extNums[vendor][extKey{outer: a.Type, num: num}]
	}
	if e == nil || e.attrType == typeEVS {
		return fmt.Sprintf("{%sAttr: #%s%s, Value: %s}", prefix, oid, flags, avpBinary.String(p, AVP{Value: data}))
	}
	if continued {
		return fmt.Sprintf("{%sAttr: %s #%s%s, Value: %s}", prefix, e.name, oid, flags, avpBinary.String(p, AVP{Value: data}))
	}
	return fmt.Sprintf("{%sAttr: %s #%s%s, Value: %s}", prefix, e.name, oid, flags, d.formatExtValue(p, vendor, e, data))
}

// chainStart returns the data of the first fragment if a, an AVP of p, continues a long value.
func chainStart(p *Packet, a AVP) ([]byte, bool) {
	if p == nil || len(a.Value) == 0 {
		return nil, false
	}
	if c := p.chain; c != nil && len(c.cur) == len(a.Value) && &c.cur[0] == &a.Value[0] {
		return c.start, c.start != nil
	}
	var first []byte
	var firstExt uint8
	chained, found := false, false
	p.EachAVP(func(x AVP) bool {
		ext, more, data, ok := splitExtended(x.Value, true)
		if x.Type == a.Type && len(x.Value) == len(a.Value) && &x.Value[0] == &a.Value[0] {
			found = chained && ok && ext == firstExt
			return false
		}
		if x.Type != a.Type || !ok || chained && ext != firstExt {
			chained = false
			return true
		}
		switch {
		case chained && !more:
			chained = false
		case !chained && more:
			first, firstExt, chained = data, ext, true
		}
		return true
	})
	return first, found
}

// chainState follows long-extended chains through the AVPs of a packet in order,
// as chainStart does for one AVP.
type chainState struct {
	typ   AttributeType
	ext   uint8
	first []byte // data of the open chain's first fragment, nil if none
	cur   []byte // value of the last AVP passed to next
	start []byte // first fragment of the chain cur continues, nil if none
}

func (c *chainState) next(a AVP) {
	ext, more, data, ok := splitExtended(a.Value, true)
	c.cur, c.start = a.Value, nil
	if c.first != nil && a.Type == c.typ {
		if !ok || ext != c.ext {
			c.first = nil
			return
		}
		c.start = c.first
		if !more {
			c.first = nil
		}
		return
	}
	c.first = nil
	if ok && more {
		c.typ, c.ext, c.first = a.Type, ext, data
	}
}

// formatExtValue renders the value of extended attribute e; caller holds the lock.
func (d *Dictionary) formatExtValue(p *Packet, vendor VendorID, e *extAttr, v []byte) string {
	if t := d.rootTLV(vendor, e.name); t != nil {
		return t.format(p, v)
	}
	if e.encrypt != encryptNone {
		return avpBinary.String(p, AVP{Value: v})
	}
	handler := handlerForValue(e.attrType, v)
	if name, ok := enumName(handler, v, e.constName); ok {
		return name
	}
	return handler.String(p, AVP{Value: v})
}

// lookupExtended returns the definition of extended attribute attrName of vendorName ("" for standard); caller holds the lock.
func (d *Dictionary) lookupExtended(vendorName, attrName string) (VendorID, *extAttr, error) {
	var vendorID VendorID
	if vendorName != "" {
		id, ok := d.vendorID[vendorName]
		if !ok {
			return 0, nil, fmt.Errorf("%w: %s", ErrUnknownVendor, vendorName)
		}
		vendorID = id
	}
	e := d.extAttrs[vendorID][attrName]
	if e == nil {
		return vendorID, nil, fmt.Errorf("%w: %s", ErrUnknownAttribute, qualifiedName(vendorName, attrName))
	}
	return vendorID, e, nil
}

// encodeExtended encodes value for extended attribute e; caller holds the lock.
func encodeExtended(e *extAttr, qname string, tagged bool, value string) (ExtendedAttr, error) {
	if tagged {
		return ExtendedAttr{}, fmt.Errorf("%w: attribute %s has no tag", ErrInvalidTag, qname)
	}
	if e.encrypt != encryptNone {
		return ExtendedAttr{}, fmt.Errorf("%w: encrypted attribute %s", ErrUnsupportedAttributeType, qname)
	}
	handler := attrTypeHandlers[e.attrType]
	if handler == nil {
		return ExtendedAttr{}, fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, e.attrType, qname)
	}
	v, err := encodeValue(handler, e.constID, 0, value)
	if err != nil {
		return ExtendedAttr{}, fmt.Errorf("%w for attribute %s", err, qname)
	}
	x := e.id
	x.Value = v
	if err := x.check(); err != nil {
		return ExtendedAttr{}, fmt.Errorf("%w for attribute %s", err, qname)
	}
	return x, nil
}

// NewExtended is like ParseExtended but logs the error and returns the zero ExtendedAttr.
func (d *Dictionary) NewExtended(vendorName, attrName, attrValue string) ExtendedAttr {
	e, err := d.ParseExtended(vendorName, attrName, attrValue)
	if err != nil {
		logger().Warn("radius: NewExtended", "error", err)
	}
	return e
}

// ParseExtended builds an RFC 6929 extended attribute from its name and a string value; integers may be VALUE names.
//
// vendorName is "" for standard extended attributes, otherwise an Extended-Vendor-Specific
// attribute is built. Add it with Packet.AddExtended, which splits long values.
func (d *Dictionary) ParseExtended(vendorName, attrName, attrValue string) (ExtendedAttr, error) {
	attrName, _, tagged, err := splitTagName(attrName)
	if err != nil {
		return ExtendedAttr{}, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, e, err := d.lookupExtended(vendorName, attrName)
	if err != nil {
		return ExtendedAttr{}, err
	}
	return encodeExtended(e, qualifiedName(vendorName, attrName), tagged, attrValue)
}

// GetExtended returns a copy of the first value of extended attribute attrName in p, joining long values.
//
// vendorName is "" for standard extended attributes.
func (d *Dictionary) GetExtended(p *Packet, vendorName, attrName string) ([]byte, bool) {
	d.mu.RLock()
	_, e, err := d.lookupExtended(vendorName, attrName)
	var id ExtendedAttr
	if err == nil {
		id = e.id
	}
	d.mu.RUnlock()
	if err != nil {
		return nil, false
	}
	var found []byte
	ok := false
	eachExtendedValue(p, id, func(v []byte) bool {
		found, ok = bytes.Clone(v), true
		return false
	})
	return found, ok
}

var avpExtended AvpExtended

// AvpExtended formats RFC 6929 extended attributes (types 241-246) using the default dictionary.
type AvpExtended struct{}

func (s AvpExtended) Value(p *Packet, a AVP) any {
	// as-is
	return a.Value
}

func (s AvpExtended) String(p *Packet, a AVP) string {
	d := GetDefaultDictionary()
	if d == nil {
		return avpBinary.String(p, a)
	}
	return d.DecodeAVPValue(p, a)
}

// FromString returns v as raw octets; use ParseExtended to build a value by attribute name.
func (s AvpExtended) FromString(v string) []byte {
	return []byte(v)
}

// parseExtendedAVP encodes extended attribute e as one AVP; caller holds the lock.
func parseExtendedAVP(e *extAttr, attrName string, tagged bool, value string) (AVP, error) {
	x, err := encodeExtended(e, attrName, tagged, value)
	if err != nil {
		return AVP{}, err
	}
	avps := x.ToAVPList()
	if len(avps) != 1 {
		return AVP{}, fmt.Errorf("%w: %s too long for one attribute, use ParseExtended", ErrInvalidValue, attrName)
	}
	return avps[0], nil
}
