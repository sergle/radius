package radius

import (
	"strconv"
)

type AttributeType uint8

const (
	AttrUserName             AttributeType = 1
	AttrUserPassword         AttributeType = 2
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
			handler := attr_type_handlers[typeName]
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

func (a AttributeType) String() string {
	return getAttributeTypeDesc(a).name
}
