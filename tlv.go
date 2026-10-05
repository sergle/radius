package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	tlvHeaderLen = 2   // sub-attribute type + length
	maxTLVLen    = 255 // max sub-attribute length, header included
	typeTLV      = "tlv"
	// VENDOR format the TLV support assumes (1-byte type and length)
	defaultVendorFormat = "format=1,1"
)

// tlvAttr is a dictionary attribute of type "tlv" or a sub-attribute of one.
type tlvAttr struct {
	name      string
	num       uint8
	attrType  string
	parent    *tlvAttr // nil for a top-level attribute
	children  map[uint8]*tlvAttr
	constID   map[string]uint32
	constName map[uint32]string
}

// tlvBlock is an open BEGIN-TLV block; attr is nil when its children are ignored.
type tlvBlock struct {
	name string
	attr *tlvAttr
}

// TLVValue is a sub-attribute name and value for ParseTLV; use keyed fields,
// e.g. TLVValue{Name: "X", Value: "1"}. A nested TLV's own name with an empty
// Value starts a new instance of it.
type TLVValue struct {
	Name  string
	Value string
}

var avpTLV AvpTLV

// AvpTLV formats "tlv" attributes using the default dictionary.
type AvpTLV struct{}

func (s AvpTLV) Value(p *Packet, a AVP) interface{} {
	// as-is
	return a.Value
}

func (s AvpTLV) String(p *Packet, a AVP) string {
	d := GetDefaultDictionary()
	if d == nil {
		return avpBinary.String(p, a)
	}
	return d.DecodeAVPValue(p, a)
}

// FromString returns v as raw octets; use ParseTLV to build a value from sub-attributes.
func (s AvpTLV) FromString(v string) []byte {
	return []byte(v)
}

// addChild links child under t; a number already taken keeps its first definition.
func (t *tlvAttr) addChild(child *tlvAttr) bool {
	if old, ok := t.children[child.num]; ok {
		logger().Warn("radius: ignoring duplicate sub-attribute number", "attribute", child.name, "existing", old.name, "parent", t.name)
		return false
	}
	if t.children == nil {
		t.children = make(map[uint8]*tlvAttr)
	}
	child.parent = t
	t.children[child.num] = child
	return true
}

// addValue records a VALUE name for t.
func (t *tlvAttr) addValue(name string, v uint32) {
	if t.constID == nil {
		t.constID = make(map[string]uint32)
		t.constName = make(map[uint32]string)
	}
	t.constID[name] = v
	t.constName[v] = name
}

// root returns the top-level attribute of t.
func (t *tlvAttr) root() *tlvAttr {
	for t.parent != nil {
		t = t.parent
	}
	return t
}

// path returns the sub-attribute numbers from the top-level attribute down to t.
func (t *tlvAttr) path() []uint8 {
	var nums []uint8
	for ; t.parent != nil; t = t.parent {
		nums = append(nums, t.num)
	}
	for i, j := 0, len(nums)-1; i < j; i, j = i+1, j-1 {
		nums[i], nums[j] = nums[j], nums[i]
	}
	return nums
}

// format renders value as its sub-attributes, or as octets if it is malformed; caller holds the lock.
func (t *tlvAttr) format(p *Packet, value []byte) string {
	if !validTLV(value) {
		return avpBinary.String(p, AVP{Value: value})
	}
	var b strings.Builder
	b.WriteByte('{')
	walkTLV(value, func(num uint8, v []byte) bool {
		if b.Len() > 1 {
			b.WriteString(", ")
		}
		child := t.children[num]
		if child == nil {
			b.WriteString("#" + strconv.Itoa(int(num)) + ": " + avpBinary.String(p, AVP{Value: v}))
			return true
		}
		b.WriteString(child.name + ": " + child.formatValue(p, v))
		return true
	})
	b.WriteByte('}')
	return b.String()
}

// formatValue renders value of sub-attribute t; caller holds the lock.
func (t *tlvAttr) formatValue(p *Packet, v []byte) string {
	if t.attrType == typeTLV {
		return t.format(p, v)
	}
	handler := handlerForValue(t.attrType, v)
	if name, ok := enumName(handler, v, t.constName); ok {
		return name
	}
	return handler.String(p, AVP{Value: v})
}

// walkTLV calls fn for each sub-attribute of value until fn returns false or value is malformed.
func walkTLV(value []byte, fn func(num uint8, v []byte) bool) {
	for len(value) >= tlvHeaderLen {
		l := int(value[1])
		if l < tlvHeaderLen || l > len(value) {
			return
		}
		if !fn(value[0], value[tlvHeaderLen:l]) {
			return
		}
		value = value[l:]
	}
}

// validTLV reports whether value is a non-empty sequence of well-formed sub-attributes.
func validTLV(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	rest := len(value)
	walkTLV(value, func(num uint8, v []byte) bool {
		rest -= len(v) + tlvHeaderLen
		return true
	})
	return rest == 0
}

// findTLV returns the first sub-attribute of value at path.
func findTLV(value []byte, path []uint8) ([]byte, bool) {
	if len(path) == 0 {
		return value, true
	}
	if !validTLV(value) {
		return nil, false
	}
	var found []byte
	ok := false
	walkTLV(value, func(num uint8, v []byte) bool {
		if num == path[0] {
			found, ok = findTLV(v, path[1:])
		}
		return !ok
	})
	return found, ok
}

// tlvNode is a sub-attribute being encoded; containers hold children instead of a value.
type tlvNode struct {
	num       uint8
	container bool
	value     []byte
	children  []*tlvNode
}

// add appends value at path, reusing the last container on each level if it has the same number.
func (n *tlvNode) add(path []uint8, value []byte) {
	p := n.parent(path)
	p.children = append(p.children, &tlvNode{num: path[len(path)-1], value: value})
}

// addContainer appends a new, empty container at path.
func (n *tlvNode) addContainer(path []uint8) {
	p := n.parent(path)
	p.children = append(p.children, &tlvNode{num: path[len(path)-1], container: true})
}

// parent returns the container for the last element of path, creating missing ones.
func (n *tlvNode) parent(path []uint8) *tlvNode {
	for _, num := range path[:len(path)-1] {
		k := len(n.children)
		if k == 0 || !n.children[k-1].container || n.children[k-1].num != num {
			n.children = append(n.children, &tlvNode{num: num, container: true})
			k++
		}
		n = n.children[k-1]
	}
	return n
}

// appendChildren appends the encoded children of n to b.
func (n *tlvNode) appendChildren(b []byte) ([]byte, error) {
	for _, c := range n.children {
		start := len(b)
		b = append(b, c.num, 0)
		if c.container {
			if len(c.children) == 0 {
				return nil, fmt.Errorf("%w: empty nested TLV %d", ErrInvalidValue, c.num)
			}
			var err error
			if b, err = c.appendChildren(b); err != nil {
				return nil, err
			}
		} else {
			b = append(b, c.value...)
		}
		l := len(b) - start
		if l > maxTLVLen {
			return nil, fmt.Errorf("%w: sub-attribute %d too long", ErrInvalidValue, c.num)
		}
		b[start+1] = uint8(l)
	}
	return b, nil
}

// lookupTLV returns the TLV definition attrName of vendorName ("" for standard attributes); caller holds the lock.
func (d *Dictionary) lookupTLV(vendorName, attrName string) (VendorID, *tlvAttr, error) {
	var vendorID VendorID
	if vendorName != "" {
		id, ok := d.vendorID[vendorName]
		if !ok {
			return 0, nil, fmt.Errorf("%w: %s", ErrUnknownVendor, vendorName)
		}
		vendorID = id
	}
	t := d.tlvAttrs[vendorID][attrName]
	if t == nil {
		return vendorID, nil, fmt.Errorf("%w: %s", ErrUnknownAttribute, qualifiedName(vendorName, attrName))
	}
	return vendorID, t, nil
}

// qualifiedName returns "vendor/attribute", or attrName for standard attributes.
func qualifiedName(vendorName, attrName string) string {
	if vendorName == "" {
		return attrName
	}
	return vendorName + "/" + attrName
}

// rootTLV returns the TLV definition of top-level attribute attrName, or nil; caller holds the lock.
func (d *Dictionary) rootTLV(vendorID VendorID, attrName string) *tlvAttr {
	t := d.tlvAttrs[vendorID][attrName]
	if t == nil || t.parent != nil {
		return nil
	}
	return t
}

// NewTLV is like ParseTLV but logs the error and returns the zero AVP.
func (d *Dictionary) NewTLV(vendorName, attrName string, values ...TLVValue) AVP {
	avp, err := d.ParseTLV(vendorName, attrName, values...)
	if err != nil {
		logger().Warn("radius: NewTLV", "error", err)
	}
	return avp
}

// ParseTLV encodes sub-attributes (at any depth) of the "tlv" attribute attrName into one AVP.
//
// vendorName is "" for standard attributes, otherwise a Vendor-Specific AVP is returned.
// Consecutive values under the same nested TLV share one instance of it; the
// nested TLV's own name with an empty value starts a new instance.
func (d *Dictionary) ParseTLV(vendorName, attrName string, values ...TLVValue) (AVP, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	vendorID, root, err := d.lookupTLV(vendorName, attrName)
	if errors.Is(err, ErrUnknownAttribute) {
		attrType := d.attrType[attrName]
		if vendorName != "" {
			attrType = d.vsaAttrType[vendorID][attrName]
		}
		if attrType != "" {
			return AVP{}, fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, attrType, qualifiedName(vendorName, attrName))
		}
	}
	if err != nil {
		return AVP{}, err
	}
	if root.parent != nil {
		return AVP{}, fmt.Errorf("%w: %s is a sub-attribute", ErrUnknownAttribute, attrName)
	}
	if len(values) == 0 {
		return AVP{}, fmt.Errorf("%w: no sub-attributes for %s", ErrInvalidValue, attrName)
	}

	var top tlvNode
	for _, v := range values {
		t := d.tlvAttrs[vendorID][v.Name]
		if t == nil || t.parent == nil || t.root() != root {
			return AVP{}, fmt.Errorf("%w: %s in %s", ErrUnknownAttribute, v.Name, attrName)
		}
		if t.attrType == typeTLV {
			if v.Value != "" {
				return AVP{}, fmt.Errorf("%w: nested TLV %s takes no value", ErrInvalidValue, v.Name)
			}
			top.addContainer(t.path())
			continue
		}
		handler := attrTypeHandlers[t.attrType]
		if handler == nil {
			return AVP{}, fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, t.attrType, v.Name)
		}
		b, err := encodeValue(handler, t.constID, 0, v.Value)
		if err != nil {
			return AVP{}, fmt.Errorf("%w for attribute %s", err, v.Name)
		}
		top.add(t.path(), b)
	}
	value, err := top.appendChildren(nil)
	if err != nil {
		return AVP{}, fmt.Errorf("%w in %s", err, attrName)
	}

	if vendorName == "" {
		if len(value) > maxAVPValueLen {
			return AVP{}, fmt.Errorf("%w: %s too long", ErrInvalidValue, attrName)
		}
		return AVP{Type: AttributeType(root.num), Value: value}, nil
	}
	if len(value) > maxAVPValueLen-vsaHeaderSize {
		return AVP{}, fmt.Errorf("%w: %s too long", ErrInvalidValue, attrName)
	}
	return VSA{Vendor: vendorID, Type: VendorAttr(root.num), Value: value}.ToAVP(), nil
}

// GetTLV returns a copy of the first value of TLV sub-attribute attrName in p.
//
// vendorName is "" for sub-attributes of standard attributes.
func (d *Dictionary) GetTLV(p *Packet, vendorName, attrName string) ([]byte, bool) {
	d.mu.RLock()
	vendorID, t, err := d.lookupTLV(vendorName, attrName)
	if err != nil {
		d.mu.RUnlock()
		return nil, false
	}
	root := t.root()
	path := t.path()
	d.mu.RUnlock()

	var found []byte
	ok := false
	p.EachAVP(func(a AVP) bool {
		if vendorName == "" {
			if a.Type == AttributeType(root.num) {
				found, ok = findTLV(a.Value, path)
			}
			return !ok
		}
		if a.Type != AttrVendorSpecific || len(a.Value) < vendorIDLen ||
			VendorID(binary.BigEndian.Uint32(a.Value)) != vendorID {
			return true
		}
		// a Vendor-Specific attribute may hold several vendor sub-attributes
		walkTLV(a.Value[vendorIDLen:], func(num uint8, v []byte) bool {
			if num == root.num {
				found, ok = findTLV(v, path)
			}
			return !ok
		})
		return !ok
	})
	if !ok {
		return nil, false
	}
	return bytes.Clone(found), true
}

// GetTLVString is like GetTLV but formats the value, using VALUE names and nested sub-attributes.
func (d *Dictionary) GetTLVString(p *Packet, vendorName, attrName string) (string, bool) {
	v, ok := d.GetTLV(p, vendorName, attrName)
	if !ok {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, t, err := d.lookupTLV(vendorName, attrName)
	if err != nil {
		return "", false
	}
	return t.formatValue(p, v), true
}
