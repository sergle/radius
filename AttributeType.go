package radius

import (
	"strconv"
)

// AttributeType is the RADIUS attribute Type field.
type AttributeType uint8

const (
	AttrUserName             AttributeType = 1
	AttrUserPassword         AttributeType = 2
	AttrCHAPPassword         AttributeType = 3
	AttrNASIPAddress         AttributeType = 4
	AttrNASPort              AttributeType = 5
	AttrServiceType          AttributeType = 6
	AttrReplyMessage         AttributeType = 18
	AttrVendorSpecific       AttributeType = 26
	AttrCalledStationId      AttributeType = 30
	AttrCallingStationId     AttributeType = 31
	AttrNASIdentifier        AttributeType = 32
	AttrAcctStatusType       AttributeType = 40
	AttrAcctInputOctets      AttributeType = 42
	AttrAcctOutputOctets     AttributeType = 43
	AttrAcctSessionId        AttributeType = 44
	AttrAcctTerminateCause   AttributeType = 49
	AttrAcctInputGigawords   AttributeType = 52
	AttrAcctOutputGigawords  AttributeType = 53
	AttrCHAPChallenge        AttributeType = 60
	AttrNASPortType          AttributeType = 61
	AttrEAPMessage           AttributeType = 79
	AttrMessageAuthenticator AttributeType = 80
	AttrNASPortId            AttributeType = 87
)

func getAttributeTypeDesc(t AttributeType) attributeTypeDesc {
	defaultDictionaryMu.RLock()
	d := defaultDictionary
	defaultDictionaryMu.RUnlock()

	if d != nil {
		name := d.GetAttributeName(t)
		if name != "" {
			typeName := d.GetAttributeType(name)
			handler := attrTypeHandlers[typeName]
			if handler == nil {
				handler = avpBinary
			}
			return attributeTypeDesc{name: name, dataType: handler}
		}
	}

	return attributeTypeDesc{
		name:     "Unknown " + strconv.Itoa(int(t)),
		dataType: avpBinary,
	}
}

type attributeTypeDesc struct {
	name     string
	dataType avpDataType
}

// String returns the attribute name from the current default dictionary when available.
// If no dictionary is loaded or the attribute is unknown, it returns a fallback name.
func (a AttributeType) String() string {
	return getAttributeTypeDesc(a).name
}
