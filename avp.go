package radius

import (
	"errors"
	"strconv"
)

// AVP represents a RADIUS Attribute-Value Pair.
//
// The on-the-wire attribute format is: Type (1 byte), Length (1 byte), Value (Length-2 bytes).
type AVP struct {
	Type  AttributeType
	Value []byte
}

// Copy returns a deep copy of the AVP (including its Value bytes).
func (a AVP) Copy() AVP {
	value := make([]byte, len(a.Value))
	copy(value, a.Value)
	return AVP{
		Type:  a.Type,
		Value: value,
	}
}

// Encode writes the AVP to b and returns the number of bytes written,
// or ErrBufferTooSmall if it doesn't fit.
func (a AVP) Encode(b []byte) (n int, err error) {
	fullLen := len(a.Value) + 2 //type and length
	if fullLen > 255 || fullLen < 2 {
		return 0, errors.New("value too big for attribute")
	}
	if len(b) < fullLen {
		return 0, ErrBufferTooSmall
	}
	b[0] = uint8(a.Type)
	b[1] = uint8(fullLen)
	copy(b[2:], a.Value)
	return fullLen, err
}

// Decode decodes the AVP value using the current default dictionary.
func (a AVP) Decode(p *Packet) interface{} {
	return getAttributeTypeDesc(a.Type).dataType.Value(p, a)
}

// String returns a human-readable representation of the AVP.
func (a AVP) String() string {
	return a.StringWithPacket(nil)
}

// StringWithPacket returns a human-readable representation of the AVP that may
// depend on packet context. It decrypts encrypted values (e.g. User-Password)
// with p, so it isn't meant for logs: use StringMasked.
func (a AVP) StringWithPacket(p *Packet) string {
	desc := getAttributeTypeDesc(a.Type)
	if p.masksAttr(a.Type) {
		return "AVP type: " + desc.name + " " + maskedValue
	}
	return "AVP type: " + desc.name + " " + desc.dataType.String(p, a)
}

// StringMasked is like StringWithPacket but shows encrypted values as *****.
func (a AVP) StringMasked(p *Packet) string {
	return a.StringWithPacket(p.withMasked())
}

type avpDataType interface {
	Value(p *Packet, a AVP) interface{}
	String(p *Packet, a AVP) string
	FromString(v string) []byte
}

// enums:

// enumString returns the name of e, or "unknown code N" if it has none.
func enumString[E ~uint32](names map[E]string, e E) string {
	if name, ok := names[e]; ok {
		return name
	}
	return "unknown code " + strconv.FormatUint(uint64(e), 10)
}

// AcctStatusTypeEnum is the decoded form of Acct-Status-Type.
type AcctStatusTypeEnum uint32

const (
	AcctStatusTypeEnumStart         AcctStatusTypeEnum = 1
	AcctStatusTypeEnumStop          AcctStatusTypeEnum = 2
	AcctStatusTypeEnumInterimUpdate AcctStatusTypeEnum = 3
	AcctStatusTypeEnumAccountingOn  AcctStatusTypeEnum = 7
	AcctStatusTypeEnumAccountingOff AcctStatusTypeEnum = 8
	// RFC 2867 - tunnel accounting status types
	AcctStatusTypeEnumTunnelStart      AcctStatusTypeEnum = 9
	AcctStatusTypeEnumTunnelStop       AcctStatusTypeEnum = 10
	AcctStatusTypeEnumTunnelReject     AcctStatusTypeEnum = 11
	AcctStatusTypeEnumTunnelLinkStart  AcctStatusTypeEnum = 12
	AcctStatusTypeEnumTunnelLinkStop   AcctStatusTypeEnum = 13
	AcctStatusTypeEnumTunnelLinkReject AcctStatusTypeEnum = 14
)

var acctStatusTypeNames = map[AcctStatusTypeEnum]string{
	AcctStatusTypeEnumStart:            "Start",
	AcctStatusTypeEnumStop:             "Stop",
	AcctStatusTypeEnumInterimUpdate:    "InterimUpdate",
	AcctStatusTypeEnumAccountingOn:     "AccountingOn",
	AcctStatusTypeEnumAccountingOff:    "AccountingOff",
	AcctStatusTypeEnumTunnelStart:      "Tunnel-Start",
	AcctStatusTypeEnumTunnelStop:       "Tunnel-Stop",
	AcctStatusTypeEnumTunnelReject:     "Tunnel-Reject",
	AcctStatusTypeEnumTunnelLinkStart:  "Tunnel-Link-Start",
	AcctStatusTypeEnumTunnelLinkStop:   "Tunnel-Link-Stop",
	AcctStatusTypeEnumTunnelLinkReject: "Tunnel-Link-Reject",
}

// String returns the standard name for the accounting status value.
func (e AcctStatusTypeEnum) String() string { return enumString(acctStatusTypeNames, e) }

// NASPortTypeEnum is the decoded form of NAS-Port-Type.
type NASPortTypeEnum uint32

const (
	NASPortTypeEnumAsync            NASPortTypeEnum = 0
	NASPortTypeEnumSync             NASPortTypeEnum = 1
	NASPortTypeEnumISDNSync         NASPortTypeEnum = 2
	NASPortTypeEnumISDNSyncV120     NASPortTypeEnum = 3
	NASPortTypeEnumISDNSyncV110     NASPortTypeEnum = 4
	NASPortTypeEnumVirtual          NASPortTypeEnum = 5
	NASPortTypeEnumPIAFS            NASPortTypeEnum = 6
	NASPortTypeEnumHDLCClearChannel NASPortTypeEnum = 7
	NASPortTypeEnumEthernet         NASPortTypeEnum = 15
	NASPortTypeEnumxDSL             NASPortTypeEnum = 16
	NASPortTypeEnumCable            NASPortTypeEnum = 17
	NASPortTypeEnumWirelessOther    NASPortTypeEnum = 18
	NASPortTypeEnumWireless80211    NASPortTypeEnum = 19
	NASPortTypeEnumTokenRing        NASPortTypeEnum = 20
	NASPortTypeEnumFDDI             NASPortTypeEnum = 21
)

var nasPortTypeNames = map[NASPortTypeEnum]string{
	NASPortTypeEnumAsync:            "Async",
	NASPortTypeEnumSync:             "Sync",
	NASPortTypeEnumISDNSync:         "ISDNSync",
	NASPortTypeEnumISDNSyncV120:     "ISDNSyncV120",
	NASPortTypeEnumISDNSyncV110:     "ISDNSyncV110",
	NASPortTypeEnumVirtual:          "Virtual",
	NASPortTypeEnumPIAFS:            "PIAFS",
	NASPortTypeEnumHDLCClearChannel: "HDLCClearChannel",
	NASPortTypeEnumEthernet:         "Ethernet",
	NASPortTypeEnumxDSL:             "xDSL",
	NASPortTypeEnumCable:            "Cable",
	NASPortTypeEnumWirelessOther:    "Wireless-Other",
	NASPortTypeEnumWireless80211:    "Wireless-IEEE-802.11",
	NASPortTypeEnumTokenRing:        "Token-Ring",
	NASPortTypeEnumFDDI:             "FDDI",
}

// String returns the standard name for the NAS port type value.
func (e NASPortTypeEnum) String() string { return enumString(nasPortTypeNames, e) }

// ServiceTypeEnum is the decoded form of Service-Type.
type ServiceTypeEnum uint32

const (
	ServiceTypeEnumLogin            ServiceTypeEnum = 1
	ServiceTypeEnumFramed           ServiceTypeEnum = 2
	ServiceTypeEnumCallbackLogin    ServiceTypeEnum = 3
	ServiceTypeEnumCallbackFramed   ServiceTypeEnum = 4
	ServiceTypeEnumOutbound         ServiceTypeEnum = 5
	ServiceTypeEnumAdministrative   ServiceTypeEnum = 6
	ServiceTypeEnumNASPrompt        ServiceTypeEnum = 7
	ServiceTypeEnumAuthenticateOnly ServiceTypeEnum = 8
	ServiceTypeEnumCallCheck        ServiceTypeEnum = 10
)

var serviceTypeNames = map[ServiceTypeEnum]string{
	ServiceTypeEnumLogin:            "Login",
	ServiceTypeEnumFramed:           "Framed",
	ServiceTypeEnumCallbackLogin:    "CallbackLogin",
	ServiceTypeEnumCallbackFramed:   "CallbackFramed",
	ServiceTypeEnumOutbound:         "Outbound",
	ServiceTypeEnumAdministrative:   "Administrative",
	ServiceTypeEnumNASPrompt:        "NAS-Prompt",
	ServiceTypeEnumAuthenticateOnly: "Authenticate-Only",
	ServiceTypeEnumCallCheck:        "Call-Check",
}

// String returns the standard name for the service type value.
func (e ServiceTypeEnum) String() string { return enumString(serviceTypeNames, e) }

// PromptEnum is the decoded form of Prompt (RFC 2869).
type PromptEnum uint32

const (
	PromptEnumNoEcho PromptEnum = 0
	PromptEnumEcho   PromptEnum = 1
)

var promptNames = map[PromptEnum]string{
	PromptEnumNoEcho: "No-Echo",
	PromptEnumEcho:   "Echo",
}

// String returns the standard name for the prompt value.
func (e PromptEnum) String() string { return enumString(promptNames, e) }

// TunnelTypeEnum is the decoded form of Tunnel-Type (RFC 2868).
type TunnelTypeEnum uint32

const (
	TunnelTypeEnumPPTP    TunnelTypeEnum = 1
	TunnelTypeEnumL2F     TunnelTypeEnum = 2
	TunnelTypeEnumL2TP    TunnelTypeEnum = 3
	TunnelTypeEnumATMP    TunnelTypeEnum = 4
	TunnelTypeEnumVTP     TunnelTypeEnum = 5
	TunnelTypeEnumAH      TunnelTypeEnum = 6
	TunnelTypeEnumIPIP    TunnelTypeEnum = 7
	TunnelTypeEnumMinIPIP TunnelTypeEnum = 8
	TunnelTypeEnumESP     TunnelTypeEnum = 9
	TunnelTypeEnumGRE     TunnelTypeEnum = 10
	TunnelTypeEnumDVS     TunnelTypeEnum = 11
	TunnelTypeEnumIPInIP  TunnelTypeEnum = 12
	TunnelTypeEnumVLAN    TunnelTypeEnum = 13
)

var tunnelTypeNames = map[TunnelTypeEnum]string{
	TunnelTypeEnumPPTP:    "PPTP",
	TunnelTypeEnumL2F:     "L2F",
	TunnelTypeEnumL2TP:    "L2TP",
	TunnelTypeEnumATMP:    "ATMP",
	TunnelTypeEnumVTP:     "VTP",
	TunnelTypeEnumAH:      "AH",
	TunnelTypeEnumIPIP:    "IP-IP",
	TunnelTypeEnumMinIPIP: "MIN-IP-IP",
	TunnelTypeEnumESP:     "ESP",
	TunnelTypeEnumGRE:     "GRE",
	TunnelTypeEnumDVS:     "DVS",
	TunnelTypeEnumIPInIP:  "IP-in-IP",
	TunnelTypeEnumVLAN:    "VLAN",
}

// String returns the standard name for the tunnel type value.
func (e TunnelTypeEnum) String() string { return enumString(tunnelTypeNames, e) }

// TunnelMediumTypeEnum is the decoded form of Tunnel-Medium-Type (RFC 2868).
type TunnelMediumTypeEnum uint32

const (
	TunnelMediumTypeEnumIPv4        TunnelMediumTypeEnum = 1
	TunnelMediumTypeEnumIPv6        TunnelMediumTypeEnum = 2
	TunnelMediumTypeEnumNSAP        TunnelMediumTypeEnum = 3
	TunnelMediumTypeEnumHDLC        TunnelMediumTypeEnum = 4
	TunnelMediumTypeEnumBBN1822     TunnelMediumTypeEnum = 5
	TunnelMediumTypeEnum802         TunnelMediumTypeEnum = 6
	TunnelMediumTypeEnumE163        TunnelMediumTypeEnum = 7
	TunnelMediumTypeEnumE164        TunnelMediumTypeEnum = 8
	TunnelMediumTypeEnumF69         TunnelMediumTypeEnum = 9
	TunnelMediumTypeEnumX121        TunnelMediumTypeEnum = 10
	TunnelMediumTypeEnumIPX         TunnelMediumTypeEnum = 11
	TunnelMediumTypeEnumAppletalk   TunnelMediumTypeEnum = 12
	TunnelMediumTypeEnumDecnetIV    TunnelMediumTypeEnum = 13
	TunnelMediumTypeEnumBanyanVines TunnelMediumTypeEnum = 14
	TunnelMediumTypeEnumE164NSAP    TunnelMediumTypeEnum = 15
)

var tunnelMediumTypeNames = map[TunnelMediumTypeEnum]string{
	TunnelMediumTypeEnumIPv4:        "IPv4",
	TunnelMediumTypeEnumIPv6:        "IPv6",
	TunnelMediumTypeEnumNSAP:        "NSAP",
	TunnelMediumTypeEnumHDLC:        "HDLC",
	TunnelMediumTypeEnumBBN1822:     "BBN-1822",
	TunnelMediumTypeEnum802:         "802",
	TunnelMediumTypeEnumE163:        "E.163",
	TunnelMediumTypeEnumE164:        "E.164",
	TunnelMediumTypeEnumF69:         "F.69",
	TunnelMediumTypeEnumX121:        "X.121",
	TunnelMediumTypeEnumIPX:         "IPX",
	TunnelMediumTypeEnumAppletalk:   "Appletalk",
	TunnelMediumTypeEnumDecnetIV:    "Decnet-IV",
	TunnelMediumTypeEnumBanyanVines: "Banyan-Vines",
	TunnelMediumTypeEnumE164NSAP:    "E.164-NSAP",
}

// String returns the standard name for the tunnel medium type value.
func (e TunnelMediumTypeEnum) String() string { return enumString(tunnelMediumTypeNames, e) }

// AcctTerminateCauseEnum is the decoded form of Acct-Terminate-Cause.
type AcctTerminateCauseEnum uint32

const (
	AcctTerminateCauseEnumUserRequest             AcctTerminateCauseEnum = 1
	AcctTerminateCauseEnumLostCarrier             AcctTerminateCauseEnum = 2
	AcctTerminateCauseEnumLostService             AcctTerminateCauseEnum = 3
	AcctTerminateCauseEnumIdleTimeout             AcctTerminateCauseEnum = 4
	AcctTerminateCauseEnumSessionTimeout          AcctTerminateCauseEnum = 5
	AcctTerminateCauseEnumAdminReset              AcctTerminateCauseEnum = 6
	AcctTerminateCauseEnumAdminReboot             AcctTerminateCauseEnum = 7
	AcctTerminateCauseEnumPortError               AcctTerminateCauseEnum = 8
	AcctTerminateCauseEnumNASError                AcctTerminateCauseEnum = 9
	AcctTerminateCauseEnumNASRequest              AcctTerminateCauseEnum = 10
	AcctTerminateCauseEnumNASReboot               AcctTerminateCauseEnum = 11
	AcctTerminateCauseEnumPortUnneeded            AcctTerminateCauseEnum = 12
	AcctTerminateCauseEnumPortPreempted           AcctTerminateCauseEnum = 13
	AcctTerminateCauseEnumPortSuspended           AcctTerminateCauseEnum = 14
	AcctTerminateCauseEnumServiceUnavailable      AcctTerminateCauseEnum = 15
	AcctTerminateCauseEnumCallback                AcctTerminateCauseEnum = 16
	AcctTerminateCauseEnumUserError               AcctTerminateCauseEnum = 17
	AcctTerminateCauseEnumHostRequest             AcctTerminateCauseEnum = 18
	AcctTerminateCauseEnumSupplicantRestart       AcctTerminateCauseEnum = 19
	AcctTerminateCauseEnumReauthenticationFailure AcctTerminateCauseEnum = 20
	AcctTerminateCauseEnumPortReinitialized       AcctTerminateCauseEnum = 21
	AcctTerminateCauseEnumPortAdminDisabled       AcctTerminateCauseEnum = 22
)

var acctTerminateCauseNames = map[AcctTerminateCauseEnum]string{
	AcctTerminateCauseEnumUserRequest:             "UserRequest",
	AcctTerminateCauseEnumLostCarrier:             "LostCarrier",
	AcctTerminateCauseEnumLostService:             "LostService",
	AcctTerminateCauseEnumIdleTimeout:             "IdleTimeout",
	AcctTerminateCauseEnumSessionTimeout:          "SessionTimeout",
	AcctTerminateCauseEnumAdminReset:              "AdminReset",
	AcctTerminateCauseEnumAdminReboot:             "AdminReboot",
	AcctTerminateCauseEnumPortError:               "PortError",
	AcctTerminateCauseEnumNASError:                "NAS-Error",
	AcctTerminateCauseEnumNASRequest:              "NAS-Request",
	AcctTerminateCauseEnumNASReboot:               "NAS-Reboot",
	AcctTerminateCauseEnumPortUnneeded:            "PortUnneeded",
	AcctTerminateCauseEnumPortPreempted:           "PortPreempted",
	AcctTerminateCauseEnumPortSuspended:           "PortSuspended",
	AcctTerminateCauseEnumServiceUnavailable:      "ServiceUnavailable",
	AcctTerminateCauseEnumCallback:                "Callback",
	AcctTerminateCauseEnumUserError:               "UserError",
	AcctTerminateCauseEnumHostRequest:             "HostRequest",
	AcctTerminateCauseEnumSupplicantRestart:       "SupplicantRestart",
	AcctTerminateCauseEnumReauthenticationFailure: "ReauthenticationFailure",
	AcctTerminateCauseEnumPortReinitialized:       "PortReinitialized",
	AcctTerminateCauseEnumPortAdminDisabled:       "PortAdminDisabled",
}

// String returns the standard name for the accounting terminate cause value.
func (e AcctTerminateCauseEnum) String() string { return enumString(acctTerminateCauseNames, e) }
