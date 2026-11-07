package radius

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	tlvHeaderLen = 2   // sub-attribute type + length
	maxTLVLen    = 255 // max sub-attribute length, header included
	typeTLV      = "tlv"
)

// tlvAttr is a dictionary attribute of type "tlv" or a sub-attribute of one.
type tlvAttr struct {
	name      string
	num       uint8
	attrType  string
	encrypt   int           // encrypt= method; Packet.AddTLV encrypts, readers decrypt with the packet, if canEncrypt
	parent    *tlvAttr      // nil for a top-level attribute
	outer     AttributeType // top-level extended attribute (241-246) holding it, 0 if none
	children  map[uint8]*tlvAttr
	constID   map[string]uint32
	constName map[uint32]string
}

// tlvBlock is an open BEGIN-TLV block; attr is nil when its children are ignored.
type tlvBlock struct {
	name string
	attr *tlvAttr
}

var avpTLV AvpTLV

// AvpTLV formats "tlv" attributes using the default dictionary.
type AvpTLV struct{}

func (s AvpTLV) Value(p *Packet, a AVP) any {
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

// canEncrypt reports whether t's encrypt= method can be applied: encrypt=1 on a string, encrypt=2 on a non-TLV.
func (t *tlvAttr) canEncrypt() bool {
	switch t.encrypt {
	case encryptUserPassword:
		return t.attrType == typeString
	case encryptTunnelPassword:
		return t.attrType != typeTLV
	}
	return false
}

// unsupportedEncryption returns t or the TLV holding it that is encrypted with a method that can't be applied, or nil.
func (t *tlvAttr) unsupportedEncryption() *tlvAttr {
	for ; t != nil; t = t.parent {
		if t.encrypt != encryptNone && !t.canEncrypt() {
			return t
		}
	}
	return nil
}

// decrypt reverses the encrypt= method of t with p; it fails without p, if the method can't be applied, or on malformed ciphertext.
func (t *tlvAttr) decrypt(p *Packet, v []byte) ([]byte, bool) {
	if p == nil || !t.canEncrypt() {
		return nil, false
	}
	auth := p.cryptAuthenticator(t.encrypt)
	if t.encrypt == encryptUserPassword {
		return passwordDecrypt(p.Secret, auth, v)
	}
	return tunnelPasswordDecrypt(p.Secret, auth, v)
}

// format renders value as its sub-attributes, or as octets if it is malformed or encrypted; caller holds the lock.
func (t *tlvAttr) format(p *Packet, value []byte) string {
	if !validTLV(value) || t.encrypt != encryptNone {
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

// formatValue renders value of sub-attribute t, decrypted with p (or masked); caller holds the lock.
func (t *tlvAttr) formatValue(p *Packet, v []byte) string {
	if t.encrypt != encryptNone {
		if t.canEncrypt() && p.masks() {
			return maskedValue
		}
		plain, ok := t.decrypt(p, v)
		if !ok {
			return avpBinary.String(p, AVP{Value: v})
		}
		v = plain
	}
	if t.attrType == typeTLV {
		return t.format(p, v)
	}
	handler := handlerForValue(t.attrType, v)
	if name, ok := enumName(handler, v, t.constName); ok {
		return name
	}
	return handler.String(p, AVP{Value: v})
}

// encryptValue hides v with method (of a canEncrypt sub-attribute), p's Secret and the authenticator used for passwords.
func encryptValue(method int, p *Packet, v []byte) ([]byte, error) {
	auth, err := p.encryptAuthenticator(method)
	if err != nil {
		return nil, err
	}
	var salt [tunnelSaltLen]byte
	if method == encryptTunnelPassword {
		if salt, err = p.newSalt(); err != nil {
			return nil, err
		}
	}
	return encryptValueSalt(method, v, p.Secret, auth, salt)
}

// encryptValueSalt is encryptValue with a given salt (encrypt=2 only); sub-attributes have no tag byte.
func encryptValueSalt(method int, v []byte, secret string, auth []byte, salt [tunnelSaltLen]byte) ([]byte, error) {
	if method == encryptTunnelPassword {
		if len(v) > tunnelPasswordMaxLen {
			return nil, fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, tunnelPasswordMaxLen)
		}
		return tunnelPasswordEncrypt(0, salt, string(v), secret, auth)[tunnelTagLen:], nil
	}
	if len(v) > maxPasswordLen {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, maxPasswordLen)
	}
	return avpPassword.Encode(string(v), secret, auth), nil
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

// tlvNode is a sub-attribute being built; containers hold children instead of a value.
type tlvNode struct {
	num       uint8
	name      string
	container bool
	encrypt   int    // encrypt= method of value, kept as plaintext
	value     []byte // encoded
	children  []*tlvNode
}

// add appends c at path, reusing the last container on each level if it has the same number.
func (n *tlvNode) add(path []uint8, c *tlvNode) *tlvNode {
	for _, num := range path[:len(path)-1] {
		k := len(n.children)
		if k == 0 || !n.children[k-1].container || n.children[k-1].num != num {
			n.children = append(n.children, &tlvNode{num: num, container: true})
			k++
		}
		n = n.children[k-1]
	}
	c.num = path[len(path)-1]
	n.children = append(n.children, c)
	return c
}

// appendChildren appends the encoded children of n to b, hiding encrypted values with enc (nil refuses them).
func (n *tlvNode) appendChildren(b []byte, enc func(*tlvNode) ([]byte, error)) ([]byte, error) {
	for _, c := range n.children {
		start := len(b)
		b = append(b, c.num, 0)
		var err error
		switch {
		case c.container:
			if len(c.children) == 0 {
				return nil, fmt.Errorf("%w: empty nested TLV %s", ErrInvalidValue, c.name)
			}
			b, err = c.appendChildren(b, enc)
		case c.encrypt != encryptNone && enc == nil:
			err = fmt.Errorf("%w, use Packet.AddTLV: %s", ErrEncryptedAttribute, c.name)
		case c.encrypt != encryptNone:
			var v []byte
			if v, err = enc(c); err == nil {
				b = append(b, v...)
			}
		default:
			b = append(b, c.value...)
		}
		if err != nil {
			return nil, err
		}
		l := len(b) - start
		if l > maxTLVLen {
			return nil, fmt.Errorf("%w: sub-attribute %s too long", ErrInvalidValue, c.name)
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

// TLV builds a "tlv" attribute from sub-attributes; get one from Dictionary.ParseTLV.
// Packet.AddTLV doesn't change it, so one TLV can go into several packets; Add and AddTLV
// must not run concurrently with other uses.
type TLV struct {
	d    *Dictionary
	def  *tlvAttr // the TLV this builds; read under d.mu
	node *tlvNode
	attr *tlvTop
}

// tlvTop is the top-level attribute a TLV builds, resolved by ParseTLV.
type tlvTop struct {
	name     string
	vendorID VendorID
	vsa      bool
	num      uint8
	format   VendorFormat
	ext      *ExtendedAttr // set for extended attributes (241-246)
	root     tlvNode
}

// ParseTLV returns a builder for the "tlv" attribute attrName; vendorName is "" for standard attributes.
// Fill it with Add and AddTLV, then add it to a packet with Packet.AddTLV (which encrypts
// encrypt= sub-attributes), or encode it with ToAVP if none are encrypted.
func (d *Dictionary) ParseTLV(vendorName, attrName string) (*TLV, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	vendorID, root, err := d.lookupTLV(vendorName, attrName)
	if errors.Is(err, ErrUnknownAttribute) {
		attrType := d.attrType[attrName]
		if vendorName != "" {
			attrType = d.vsaAttrType[vendorID][attrName]
		}
		if attrType != "" {
			return nil, fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, attrType, qualifiedName(vendorName, attrName))
		}
	}
	if err != nil {
		return nil, err
	}
	if root.parent != nil {
		return nil, fmt.Errorf("%w: %s is a sub-attribute", ErrUnknownAttribute, attrName)
	}
	top := &tlvTop{name: attrName, vendorID: vendorID, vsa: vendorName != "", num: root.num, format: d.formatOf(vendorID)}
	if root.outer != 0 {
		e := d.extAttrs[vendorID][root.name].id
		top.ext = &e
	}
	return &TLV{d: d, def: root, node: &top.root, attr: top}, nil
}

// Add adds sub-attribute name (at any depth below t) with value as text, VALUE names included.
// A value under a nested TLV goes into its last instance (AddTLV starts a new one).
// encrypt= sub-attributes keep the plaintext until Packet.AddTLV encrypts them.
func (t *TLV) Add(name, value string) error {
	t.d.mu.RLock()
	defer t.d.mu.RUnlock()
	c, path, err := t.lookup(name)
	if err != nil {
		return err
	}
	if c.attrType == typeTLV {
		return fmt.Errorf("%w: nested TLV %s takes no value, use AddTLV", ErrInvalidValue, name)
	}
	handler := attrTypeHandlers[c.attrType]
	if handler == nil {
		return fmt.Errorf("%w %q for attribute %s", ErrUnsupportedAttributeType, c.attrType, name)
	}
	b, err := encodeValue(handler, c.constID, 0, value)
	if err == nil {
		err = checkTLVValueLen(c.encrypt, len(b))
	}
	if err != nil {
		return fmt.Errorf("%w for attribute %s", err, name)
	}
	t.node.add(path, &tlvNode{name: name, encrypt: c.encrypt, value: b})
	return nil
}

// AddTLV starts a new instance of nested TLV name (at any depth below t) and returns its builder.
func (t *TLV) AddTLV(name string) (*TLV, error) {
	t.d.mu.RLock()
	defer t.d.mu.RUnlock()
	c, path, err := t.lookup(name)
	if err != nil {
		return nil, err
	}
	if c.attrType != typeTLV {
		return nil, fmt.Errorf("%w: %s is not a TLV", ErrInvalidValue, name)
	}
	n := t.node.add(path, &tlvNode{name: name, container: true})
	return &TLV{d: t.d, def: c, node: n, attr: t.attr}, nil
}

// lookup returns sub-attribute name below t and its path from t; caller holds the lock.
func (t *TLV) lookup(name string) (*tlvAttr, []uint8, error) {
	c := t.d.tlvAttrs[t.attr.vendorID][name]
	depth := 0
	a := c
	for ; a != nil && a != t.def; a = a.parent {
		depth++
	}
	if a == nil || depth == 0 {
		return nil, nil, fmt.Errorf("%w: %s in %s", ErrUnknownAttribute, name, t.def.name)
	}
	if u := c.unsupportedEncryption(); u == c {
		return nil, nil, fmt.Errorf("%w: %s is encrypted with an unsupported method", ErrUnsupportedAttributeType, name)
	} else if u != nil {
		return nil, nil, fmt.Errorf("%w: %s: parent %s is encrypted with an unsupported method", ErrUnsupportedAttributeType, name, u.name)
	}
	path := c.path()
	return c, path[len(path)-depth:], nil
}

// checkTLVValueLen checks the length n of an encoded sub-attribute value (plaintext if encrypted with method).
func checkTLVValueLen(method, n int) error {
	switch {
	case method == encryptUserPassword && n > maxPasswordLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, maxPasswordLen)
	case method == encryptTunnelPassword && n > tunnelPasswordMaxLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, tunnelPasswordMaxLen)
	case tlvHeaderLen+n > maxTLVLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidValue, maxTLVLen-tlvHeaderLen)
	}
	return nil
}

// ToAVP encodes t as one AVP. Encrypted sub-attributes (use Packet.AddTLV), a value too long
// for one AVP or an empty nested TLV is logged and gives the zero AVP.
func (t *TLV) ToAVP() AVP {
	avp, err := t.toAVP()
	if err != nil {
		logger().Warn("radius: TLV.ToAVP", "error", err)
	}
	return avp
}

// toAVP implements ToAVP.
func (t *TLV) toAVP() (AVP, error) {
	avps, err := t.encode(nil)
	if err == nil && len(avps) != 1 {
		err = fmt.Errorf("%w: %s too long for one attribute, use Packet.AddTLV", ErrInvalidValue, t.attr.name)
	}
	if err != nil {
		return AVP{}, err
	}
	return avps[0], nil
}

// AddTLV adds the attribute built by tlv, encrypting encrypt= sub-attributes with p's Secret and
// authenticator (as AddTunnelPassword does), split over several AVPs if needed (WiMAX, long extended).
// For a reply, create p with request.Reply(), else encrypting returns ErrNoRequestAuthenticator;
// encrypt=2 in an Access-Request or Status-Server returns ErrTunnelPasswordInRequest.
// tlv must come from Dictionary.ParseTLV, not AddTLV; it isn't changed, and on error p is unchanged.
func (p *Packet) AddTLV(tlv *TLV) error {
	if p == nil {
		return ErrNilPacket
	}
	if tlv == nil {
		return fmt.Errorf("%w: nil TLV", ErrInvalidValue)
	}
	s := p.saveEncrypt()
	avps, err := tlv.encode(func(n *tlvNode) ([]byte, error) {
		return encryptValue(n.encrypt, p, n.value)
	})
	if err != nil {
		// undo what earlier values generated
		p.restoreEncrypt(s)
		return err
	}
	p.AddAVP(avps...)
	return nil
}

// encode returns the AVPs of t's attribute, hiding encrypted values with enc (nil refuses them).
func (t *TLV) encode(enc func(*tlvNode) ([]byte, error)) ([]AVP, error) {
	top := t.attr
	if t.node != &top.root {
		return nil, fmt.Errorf("%w: %s is nested, add %s", ErrInvalidValue, t.node.name, top.name)
	}
	if len(top.root.children) == 0 {
		return nil, fmt.Errorf("%w: no sub-attributes for %s", ErrInvalidValue, top.name)
	}
	value, err := top.root.appendChildren(nil, enc)
	if err != nil {
		return nil, fmt.Errorf("%w in %s", err, top.name)
	}
	tooLong := func() error { return fmt.Errorf("%w: %s too long", ErrInvalidValue, top.name) }
	var avps []AVP
	switch {
	case top.ext != nil:
		e := *top.ext
		e.Value = value
		if err := e.check(); err != nil {
			return nil, fmt.Errorf("%w in %s", err, top.name)
		}
		avps = e.ToAVPList()
	case !top.vsa:
		if len(value) > maxAVPValueLen {
			return nil, tooLong()
		}
		avps = []AVP{{Type: AttributeType(top.num), Value: value}}
	default:
		f := top.format.norm()
		if !f.Continuation && len(value) > f.maxValueLen() {
			return nil, tooLong()
		}
		avps = VSA{Vendor: top.vendorID, Type: VendorAttr(top.num), Value: value, Format: top.format}.ToAVPList()
	}
	n := packetHeaderLen
	for _, a := range avps {
		n += avpHeaderLen + len(a.Value)
	}
	if n > maxPacketLen {
		return nil, tooLong()
	}
	return avps, nil
}

// GetTLV returns a copy of the first value of TLV sub-attribute attrName in p.
//
// vendorName is "" for sub-attributes of standard attributes.
// An encrypted sub-attribute is decrypted with p; malformed ciphertext or an
// unsupported method is not found, but a wrong secret or authenticator isn't
// detected and gives garbage.
func (d *Dictionary) GetTLV(p *Packet, vendorName, attrName string) ([]byte, bool) {
	v, t, ok := d.findTLVValue(p, vendorName, attrName)
	if !ok {
		return nil, false
	}
	if t.encrypt != encryptNone {
		return t.decrypt(p, v)
	}
	return bytes.Clone(v), true
}

// findTLVValue returns the first raw value of sub-attribute attrName in p and its definition;
// values inside an encrypted TLV are not found.
func (d *Dictionary) findTLVValue(p *Packet, vendorName, attrName string) ([]byte, *tlvAttr, bool) {
	d.mu.RLock()
	vendorID, t, err := d.lookupTLV(vendorName, attrName)
	if err == nil && t.parent != nil && t.parent.unsupportedEncryption() != nil {
		err = ErrUnsupportedAttributeType
	}
	if err != nil {
		d.mu.RUnlock()
		return nil, nil, false
	}
	root := t.root()
	path := t.path()
	f := d.formatOf(vendorID)
	var ext ExtendedAttr
	if root.outer != 0 {
		ext = d.extAttrs[vendorID][root.name].id
	}
	d.mu.RUnlock()

	var found []byte
	ok := false
	if root.outer != 0 {
		eachExtendedValue(p, ext, func(v []byte) bool {
			found, ok = findTLV(v, path)
			return !ok
		})
	} else if vendorName == "" {
		p.EachAVP(func(a AVP) bool {
			if a.Type == AttributeType(root.num) {
				found, ok = findTLV(a.Value, path)
			}
			return !ok
		})
	} else {
		eachVSA(p, vendorID, f, func(typ VendorAttr, v []byte) bool {
			if typ == VendorAttr(root.num) {
				found, ok = findTLV(v, path)
			}
			return !ok
		})
	}
	return found, t, ok
}

// GetTLVString is like GetTLV but formats the value, using VALUE names and nested sub-attributes.
// Encrypted values that can't be decrypted are shown as octets.
func (d *Dictionary) GetTLVString(p *Packet, vendorName, attrName string) (string, bool) {
	v, t, ok := d.findTLVValue(p, vendorName, attrName)
	if !ok {
		return "", false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return t.formatValue(p, v), true
}
