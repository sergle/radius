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
	AttrFramedIPAddress      AttributeType = 8
	AttrFilterId             AttributeType = 11
	AttrFramedMTU            AttributeType = 12
	AttrReplyMessage         AttributeType = 18
	AttrState                AttributeType = 24
	AttrClass                AttributeType = 25
	AttrVendorSpecific       AttributeType = 26
	AttrSessionTimeout       AttributeType = 27
	AttrIdleTimeout          AttributeType = 28
	AttrTerminationAction    AttributeType = 29
	AttrCalledStationId      AttributeType = 30
	AttrCallingStationId     AttributeType = 31
	AttrNASIdentifier        AttributeType = 32
	AttrAcctStatusType       AttributeType = 40
	AttrAcctDelayTime        AttributeType = 41
	AttrAcctInputOctets      AttributeType = 42
	AttrAcctOutputOctets     AttributeType = 43
	AttrAcctSessionId        AttributeType = 44
	AttrAcctSessionTime      AttributeType = 46
	AttrAcctInputPackets     AttributeType = 47
	AttrAcctOutputPackets    AttributeType = 48
	AttrAcctTerminateCause   AttributeType = 49
	AttrAcctMultiSessionId   AttributeType = 50
	AttrAcctLinkCount        AttributeType = 51
	AttrAcctInputGigawords   AttributeType = 52
	AttrAcctOutputGigawords  AttributeType = 53
	AttrEventTimestamp       AttributeType = 55
	AttrCHAPChallenge        AttributeType = 60
	AttrNASPortType          AttributeType = 61
	AttrPortLimit            AttributeType = 62

	// RFC 2868 - RADIUS Attributes for Tunnel Protocol Support
	AttrTunnelType           AttributeType = 64
	AttrTunnelMediumType     AttributeType = 65
	AttrTunnelClientEndpoint AttributeType = 66
	AttrTunnelServerEndpoint AttributeType = 67

	// RFC 2867 - RADIUS Accounting Modifications for Tunnel Protocol Support
	AttrAcctTunnelConnection AttributeType = 68

	// RFC 2868 (continued)
	AttrTunnelPassword       AttributeType = 69

	// RFC 2869 - RADIUS Extensions
	AttrPrompt              AttributeType = 76
	AttrConnectInfo         AttributeType = 77

	AttrEAPMessage           AttributeType = 79
	AttrMessageAuthenticator AttributeType = 80

	// RFC 2868 (continued)
	AttrTunnelPrivateGroupID AttributeType = 81
	AttrTunnelAssignmentID   AttributeType = 82
	AttrTunnelPreference     AttributeType = 83

	AttrNASPortId            AttributeType = 87
	AttrFramedPool          AttributeType = 88

	// RFC 2867 (continued)
	AttrAcctTunnelPacketsLost AttributeType = 86

	// RFC 2869 (continued)
	AttrAcctInterimInterval AttributeType = 85

	// RFC 4372 - Chargeable User Identity
	AttrChargeableUserIdentity AttributeType = 89

	// RFC 2868 (continued)
	AttrTunnelClientAuthID AttributeType = 90
	AttrTunnelServerAuthID AttributeType = 91

	// RFC 4849 - RADIUS Filter Rule Attribute
	AttrNASFilterRule AttributeType = 92

	// RFC 3162 - RADIUS and IPv6
	AttrNASIPv6Address    AttributeType = 95
	AttrFramedInterfaceId AttributeType = 96
	AttrFramedIPv6Prefix  AttributeType = 97
	AttrLoginIPv6Host     AttributeType = 98
	AttrFramedIPv6Route   AttributeType = 99
	AttrFramedIPv6Pool    AttributeType = 100

	// RFC 5176 - Dynamic Authorization Extensions to RADIUS
	AttrErrorCause AttributeType = 101

	// RFC 5090 - RADIUS Extension for Digest Authentication
	AttrDigestResponse         AttributeType = 103
	AttrDigestRealm            AttributeType = 104
	AttrDigestNonce            AttributeType = 105
	AttrDigestResponseAuth     AttributeType = 106
	AttrDigestNextnonce        AttributeType = 107
	AttrDigestMethod           AttributeType = 108
	AttrDigestURI              AttributeType = 109
	AttrDigestQop              AttributeType = 110
	AttrDigestAlgorithm        AttributeType = 111
	AttrDigestEntityBodyHash   AttributeType = 112
	AttrDigestCNonce           AttributeType = 113
	AttrDigestNonceCount       AttributeType = 114
	AttrDigestUsername         AttributeType = 115
	AttrDigestOpaque           AttributeType = 116
	AttrDigestAuthParam        AttributeType = 117
	AttrDigestAKAAuts          AttributeType = 118
	AttrDigestDomain           AttributeType = 119
	AttrDigestStale            AttributeType = 120
	AttrDigestHA1              AttributeType = 121
	AttrSIPAOR                 AttributeType = 122
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
