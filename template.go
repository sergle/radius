package radius

import (
	"fmt"
	"maps"
	"strconv"
)

// AVPTemplate is an interface for both standard attributes and VSAs.
type AVPTemplate interface {
	Add(p *Packet, value string)
}

// AttributeTemplate stores a pre-resolved attribute definition for reuse.
type AttributeTemplate struct {
	attrType AttributeType
	handler  avpDataType
	names    map[string]uint32 // VALUE name -> number
	tag      uint8
	ext      *ExtendedAttr // set for extended attributes
}

// Add encodes the value and adds it to the provided packet; invalid values are logged and skipped.
func (t *AttributeTemplate) Add(p *Packet, value string) {
	if t.ext != nil {
		v, err := encodeValue(t.handler, t.names, 0, value)
		if err != nil {
			logger().Warn("radius: template skipped attribute", "attribute", t.attrType, "ext", t.ext.ExtType, "error", err)
			return
		}
		e := *t.ext
		e.Value = v
		p.AddExtended(e)
		return
	}
	if t.attrType == AttrUserPassword {
		p.AddPassword(value)
		return
	}
	if t.handler == avpPassword {
		p.AddAVP(AVP{Type: t.attrType, Value: avpPassword.Encode(value, p.Secret, p.cryptAuthenticator())})
		return
	}
	if t.handler == avpTunnelPassword {
		auth, err := p.encryptAuthenticator()
		var v []byte
		if err == nil {
			v, err = avpTunnelPassword.Encode(t.tag, value, p.Secret, auth)
		}
		if err != nil {
			logger().Warn("radius: template skipped attribute", "attribute", t.attrType, "error", err)
			return
		}
		p.AddAVP(AVP{Type: t.attrType, Value: v})
		return
	}
	v, err := encodeValue(t.handler, t.names, t.tag, value)
	if err != nil {
		logger().Warn("radius: template skipped attribute", "attribute", t.attrType, "error", err)
		return
	}
	p.AddAVP(AVP{Type: t.attrType, Value: v})
}

// vsaTemplate stores a pre-resolved VSA definition for reuse.
type vsaTemplate struct {
	vendorID VendorID
	vsaType  VendorAttr
	format   VendorFormat
	handler  avpDataType
	names    map[string]uint32 // VALUE name -> number
	tag      uint8
}

// Add encodes the value and adds it as a VSA to the provided packet; invalid values are logged and skipped.
func (t *vsaTemplate) Add(p *Packet, value string) {
	if t.handler == avpPassword {
		p.AddVSA(VSA{Vendor: t.vendorID, Type: t.vsaType, Value: avpPassword.Encode(value, p.Secret, p.cryptAuthenticator()), Format: t.format})
		return
	}
	v, err := encodeValue(t.handler, t.names, t.tag, value)
	if err != nil {
		logger().Warn("radius: template skipped VSA", "vendor", t.vendorID, "type", t.vsaType, "error", err)
		return
	}
	p.AddVSA(VSA{Vendor: t.vendorID, Type: t.vsaType, Value: v, Format: t.format})
}

// RequestTemplate defines a reusable structure for RADIUS requests.
type RequestTemplate struct {
	code      PacketCode
	templates []AVPTemplate
}

// CreateRequest generates a new packet from the template with the provided values.
func (t *RequestTemplate) CreateRequest(client *RadClient, values ...string) *Packet {
	req := client.NewRequest(t.code)
	t.Fill(req, values...)
	return req
}

// Fill populates an existing packet with values according to the template.
func (t *RequestTemplate) Fill(p *Packet, values ...string) {
	for i, val := range values {
		if i < len(t.templates) {
			t.templates[i].Add(p, val)
		}
	}
}

// templateHandler returns the handler for typeName; tlv values are formatted via the dictionary and encoded as raw octets.
func templateHandler(typeName string) (avpDataType, bool) {
	switch typeName {
	case typeTLV:
		return avpTLV, true
	case typeExtended, typeLongExtended:
		return avpExtended, true
	}
	h, ok := attrTypeHandlers[typeName]
	return h, ok
}

// GetTemplate creates an AttributeTemplate for the given attribute name.
func (d *Dictionary) GetTemplate(name string) (*AttributeTemplate, error) {
	name, tag, tagged, err := splitTagName(name)
	if err != nil {
		return nil, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	id, ok := d.attrID[name]
	if e := d.extAttrs[0][name]; !ok && e != nil {
		return extTemplate(e, name, tagged)
	}
	if !ok {
		return nil, fmt.Errorf("attribute %s not found in dictionary", name)
	}

	typeName, ok := d.attrType[name]
	if !ok {
		return nil, fmt.Errorf("attribute %s has no type defined", name)
	}

	handler, ok := templateHandler(typeName)
	if !ok {
		return nil, fmt.Errorf("no handler found for type %s", typeName)
	}

	if tagged && !isTagged(handler) {
		return nil, fmt.Errorf("%w: attribute %s has no tag", ErrInvalidTag, name)
	}

	return &AttributeTemplate{
		attrType: id,
		handler:  handler,
		names:    maps.Clone(d.constID[name]),
		tag:      tag,
	}, nil
}

// valueNames returns a copy of the VALUE names of attribute attrName.
func (d *Dictionary) valueNames(attrName string) map[string]uint32 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return maps.Clone(d.constID[attrName])
}

func (d *Dictionary) getVSATemplate(vendorName, attrName string) (AVPTemplate, error) {
	attrName, tag, tagged, err := splitTagName(attrName)
	if err != nil {
		return nil, fmt.Errorf("%w in attribute name", err)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	vID, ok := d.vendorID[vendorName]
	if !ok {
		return nil, fmt.Errorf("vendor %s not found in dictionary", vendorName)
	}

	aID, ok := d.vsaAttrID[vID][attrName]
	if e := d.extAttrs[vID][attrName]; !ok && e != nil {
		return extTemplate(e, vendorName+"/"+attrName, tagged)
	}
	if !ok {
		return nil, fmt.Errorf("VSA attribute %s not found for vendor %s", attrName, vendorName)
	}

	typeName, ok := d.vsaAttrType[vID][attrName]
	if !ok {
		return nil, fmt.Errorf("VSA attribute %s has no type defined", attrName)
	}

	handler, ok := templateHandler(typeName)
	if !ok {
		return nil, fmt.Errorf("no handler found for type %s", typeName)
	}

	if tagged && !isTagged(handler) {
		return nil, fmt.Errorf("%w: attribute %s/%s has no tag", ErrInvalidTag, vendorName, attrName)
	}

	format := d.formatOf(vID)
	if err := (VSA{Type: aID, Format: format}).check(); err != nil {
		return nil, fmt.Errorf("%w for attribute %s/%s", err, vendorName, attrName)
	}
	return &vsaTemplate{
		vendorID: vID,
		vsaType:  aID,
		format:   format,
		handler:  handler,
		names:    maps.Clone(d.vsaConstID[vID][attrName]),
		tag:      tag,
	}, nil
}

// vlanTemplate implements AVPTemplate for RFC 3580 §3.31 dynamic VLAN assignment.
type vlanTemplate struct{}

// Add parses value as a decimal VLAN ID and calls SetVLAN on the packet.
// If value is not a valid VLAN ID (1–4094) the call is a no-op.
func (t *vlanTemplate) Add(p *Packet, value string) {
	id, err := strconv.ParseUint(value, 10, 16)
	if err != nil || id < 1 || id > 4094 {
		return
	}
	p.SetVLAN(uint16(id))
}

// AddAttributes appends one or more attributes by name to the request template.
// Returns an error if any attribute is not found in the dictionary.
func (t *RequestTemplate) AddAttributes(d *Dictionary, names ...string) error {
	for _, name := range names {
		tmpl, err := d.GetTemplate(name)
		if err != nil {
			return err
		}
		t.templates = append(t.templates, tmpl)
	}
	return nil
}

// AddAttributeTypes appends one or more attributes by their AttributeType ID to the request template.
// The handler and VALUE names are resolved from the default dictionary; unknown attributes fall back to binary encoding.
func (t *RequestTemplate) AddAttributeTypes(attrTypes ...AttributeType) {
	for _, at := range attrTypes {
		desc := getAttributeTypeDesc(at)
		var names map[string]uint32
		if d := GetDefaultDictionary(); d != nil {
			names = d.valueNames(desc.name)
		}
		t.templates = append(t.templates, &AttributeTemplate{attrType: at, handler: desc.dataType, names: names})
	}
}

// AddVSAAttribute appends a VSA attribute by vendor and attribute name to the request template.
// Returns an error if the vendor or attribute is not found in the dictionary.
func (t *RequestTemplate) AddVSAAttribute(d *Dictionary, vendorName, attrName string) error {
	tmpl, err := d.getVSATemplate(vendorName, attrName)
	if err != nil {
		return err
	}
	t.templates = append(t.templates, tmpl)
	return nil
}

// AddVLAN appends a vlanTemplate to the request template.
func (t *RequestTemplate) AddVLAN() {
	t.templates = append(t.templates, &vlanTemplate{})
}

// CreateRequestTemplate creates a RequestTemplate for the given packet code and list of attribute names.
func (d *Dictionary) CreateRequestTemplate(code PacketCode, names ...string) (*RequestTemplate, error) {
	t := &RequestTemplate{
		code: code,
	}
	for _, name := range names {
		tmpl, err := d.GetTemplate(name)
		if err != nil {
			return nil, err
		}
		t.templates = append(t.templates, tmpl)
	}
	return t, nil
}

// extTemplate returns a template for extended attribute e; caller holds the lock.
func extTemplate(e *extAttr, qname string, tagged bool) (*AttributeTemplate, error) {
	if tagged {
		return nil, fmt.Errorf("%w: attribute %s has no tag", ErrInvalidTag, qname)
	}
	if e.encrypted {
		return nil, fmt.Errorf("%w: encrypted attribute %s", ErrUnsupportedAttributeType, qname)
	}
	handler, ok := templateHandler(e.attrType)
	if !ok {
		return nil, fmt.Errorf("no handler found for type %s", e.attrType)
	}
	id := e.id
	return &AttributeTemplate{attrType: id.Type, handler: handler, names: maps.Clone(e.constID), ext: &id}, nil
}
