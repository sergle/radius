package radius

import (
	"fmt"
)

// AVPTemplate is an interface for both standard attributes and VSAs.
type AVPTemplate interface {
	Add(p *Packet, value string)
}

// AttributeTemplate stores a pre-resolved attribute definition for reuse.
type AttributeTemplate struct {
	attrType AttributeType
	handler  avpDataType
}

// Add encodes the value and adds it to the provided packet.
func (t *AttributeTemplate) Add(p *Packet, value string) {
	if t.attrType == AttrUserPassword {
		p.AddPassword(value)
	} else {
		p.AddAVP(AVP{
			Type:  t.attrType,
			Value: t.handler.FromString(value),
		})
	}
}

// VSATemplate stores a pre-resolved VSA definition for reuse.
type VSATemplate struct {
	vendorID VendorID
	vsaType  VendorAttr
	handler  avpDataType
}

// Add encodes the value and adds it as a VSA to the provided packet.
func (t *VSATemplate) Add(p *Packet, value string) {
	vsa := VSA{
		Vendor: t.vendorID,
		Type:   t.vsaType,
		Value:  t.handler.FromString(value),
	}
	p.AddVSA(vsa)
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

// GetTemplate creates an AttributeTemplate for the given attribute name.
func (d *Dictionary) GetTemplate(name string) (*AttributeTemplate, error) {
	d.RLock()
	defer d.RUnlock()

	id, ok := d.attrID[name]
	if !ok {
		return nil, fmt.Errorf("attribute %s not found in dictionary", name)
	}

	typeName, ok := d.attrType[name]
	if !ok {
		return nil, fmt.Errorf("attribute %s has no type defined", name)
	}

	handler, ok := attrTypeHandlers[typeName]
	if !ok {
		return nil, fmt.Errorf("no handler found for type %s", typeName)
	}

	return &AttributeTemplate{
		attrType: id,
		handler:  handler,
	}, nil
}

// GetVSATemplate creates a VSATemplate for the given vendor and attribute names.
func (d *Dictionary) GetVSATemplate(vendorName, attrName string) (*VSATemplate, error) {
	d.RLock()
	defer d.RUnlock()

	vID, ok := d.vendorID[vendorName]
	if !ok {
		return nil, fmt.Errorf("vendor %s not found in dictionary", vendorName)
	}

	aID, ok := d.vsaAttrID[vID][attrName]
	if !ok {
		return nil, fmt.Errorf("VSA attribute %s not found for vendor %s", attrName, vendorName)
	}

	typeName, ok := d.vsaAttrType[vID][attrName]
	if !ok {
		return nil, fmt.Errorf("VSA attribute %s has no type defined", attrName)
	}

	handler, ok := attrTypeHandlers[typeName]
	if !ok {
		return nil, fmt.Errorf("no handler found for type %s", typeName)
	}

	return &VSATemplate{
		vendorID: vID,
		vsaType:  aID,
		handler:  handler,
	}, nil
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
