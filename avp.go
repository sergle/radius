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

// Encode writes the AVP to b and returns the number of bytes written.
//
// The caller must ensure b is large enough to hold the encoded AVP.
func (a AVP) Encode(b []byte) (n int, err error) {
	fullLen := len(a.Value) + 2 //type and length
	if fullLen > 255 || fullLen < 2 {
		return 0, errors.New("value too big for attribute")
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
	return "AVP type: " + a.Type.String() + " " + getAttributeTypeDesc(a.Type).dataType.String(nil, a)
}

// StringWithPacket returns a human-readable representation of the AVP that may
// depend on packet context (for example User-Password decryption).
func (a AVP) StringWithPacket(p *Packet) string {
	return "AVP type: " + a.Type.String() + " " + getAttributeTypeDesc(a.Type).dataType.String(p, a)
}

type avpDataType interface {
	Value(p *Packet, a AVP) interface{}
	String(p *Packet, a AVP) string
	FromString(v string) []byte
}

// enums:

// AcctStatusTypeEnum is the decoded form of Acct-Status-Type.
type AcctStatusTypeEnum uint32

const (
	AcctStatusTypeEnumStart           AcctStatusTypeEnum = 1
	AcctStatusTypeEnumStop            AcctStatusTypeEnum = 2
	AcctStatusTypeEnumInterimUpdate   AcctStatusTypeEnum = 3
	AcctStatusTypeEnumAccountingOn    AcctStatusTypeEnum = 7
	AcctStatusTypeEnumAccountingOff   AcctStatusTypeEnum = 8
	// RFC 2867 - tunnel accounting status types
	AcctStatusTypeEnumTunnelStart     AcctStatusTypeEnum = 9
	AcctStatusTypeEnumTunnelStop      AcctStatusTypeEnum = 10
	AcctStatusTypeEnumTunnelReject    AcctStatusTypeEnum = 11
	AcctStatusTypeEnumTunnelLinkStart AcctStatusTypeEnum = 12
	AcctStatusTypeEnumTunnelLinkStop  AcctStatusTypeEnum = 13
	AcctStatusTypeEnumTunnelLinkReject AcctStatusTypeEnum = 14
)

// String returns the standard name for the accounting status value.
func (e AcctStatusTypeEnum) String() string {
	switch e {
	case AcctStatusTypeEnumStart:
		return "Start"
	case AcctStatusTypeEnumStop:
		return "Stop"
	case AcctStatusTypeEnumInterimUpdate:
		return "InterimUpdate"
	case AcctStatusTypeEnumAccountingOn:
		return "AccountingOn"
	case AcctStatusTypeEnumAccountingOff:
		return "AccountingOff"
	case AcctStatusTypeEnumTunnelStart:
		return "Tunnel-Start"
	case AcctStatusTypeEnumTunnelStop:
		return "Tunnel-Stop"
	case AcctStatusTypeEnumTunnelReject:
		return "Tunnel-Reject"
	case AcctStatusTypeEnumTunnelLinkStart:
		return "Tunnel-Link-Start"
	case AcctStatusTypeEnumTunnelLinkStop:
		return "Tunnel-Link-Stop"
	case AcctStatusTypeEnumTunnelLinkReject:
		return "Tunnel-Link-Reject"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

// NASPortTypeEnum is the decoded form of NAS-Port-Type.
type NASPortTypeEnum uint32

// TODO finish it
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
)

// String returns the standard name for the NAS port type value.
func (e NASPortTypeEnum) String() string {
	switch e {
	case NASPortTypeEnumAsync:
		return "Async"
	case NASPortTypeEnumSync:
		return "Sync"
	case NASPortTypeEnumISDNSync:
		return "ISDNSync"
	case NASPortTypeEnumISDNSyncV120:
		return "ISDNSyncV120"
	case NASPortTypeEnumISDNSyncV110:
		return "ISDNSyncV110"
	case NASPortTypeEnumVirtual:
		return "Virtual"
	case NASPortTypeEnumPIAFS:
		return "PIAFS"
	case NASPortTypeEnumHDLCClearChannel:
		return "HDLCClearChannel"
	case NASPortTypeEnumEthernet:
		return "Ethernet"
	case NASPortTypeEnumCable:
		return "Cable"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

// ServiceTypeEnum is the decoded form of Service-Type.
type ServiceTypeEnum uint32

// TODO finish it
const (
	ServiceTypeEnumLogin            ServiceTypeEnum = 1
	ServiceTypeEnumFramed           ServiceTypeEnum = 2
	ServiceTypeEnumCallbackLogin    ServiceTypeEnum = 3
	ServiceTypeEnumCallbackFramed   ServiceTypeEnum = 4
	ServiceTypeEnumOutbound         ServiceTypeEnum = 5
	ServiceTypeEnumAdministrative   ServiceTypeEnum = 6
	ServiceTypeEnumNASPrompt        ServiceTypeEnum = 7
	ServiceTypeEnumAuthenticateOnly ServiceTypeEnum = 8
)

// String returns the standard name for the service type value.
func (e ServiceTypeEnum) String() string {
	switch e {
	case ServiceTypeEnumLogin:
		return "Login"
	case ServiceTypeEnumFramed:
		return "Framed"
	case ServiceTypeEnumCallbackLogin:
		return "CallbackLogin"
	case ServiceTypeEnumCallbackFramed:
		return "CallbackFramed"
	case ServiceTypeEnumOutbound:
		return "Outbound"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

// PromptEnum is the decoded form of Prompt (RFC 2869).
type PromptEnum uint32

const (
	PromptEnumNoEcho PromptEnum = 0
	PromptEnumEcho   PromptEnum = 1
)

// String returns the standard name for the prompt value.
func (e PromptEnum) String() string {
	switch e {
	case PromptEnumNoEcho:
		return "No-Echo"
	case PromptEnumEcho:
		return "Echo"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

// TunnelTypeEnum is the decoded form of Tunnel-Type (RFC 2868).
type TunnelTypeEnum uint32

const (
	TunnelTypeEnumPPTP     TunnelTypeEnum = 1
	TunnelTypeEnumL2F      TunnelTypeEnum = 2
	TunnelTypeEnumL2TP     TunnelTypeEnum = 3
	TunnelTypeEnumATMP     TunnelTypeEnum = 4
	TunnelTypeEnumVTP      TunnelTypeEnum = 5
	TunnelTypeEnumAH       TunnelTypeEnum = 6
	TunnelTypeEnumIPIP     TunnelTypeEnum = 7
	TunnelTypeEnumMinIPIP  TunnelTypeEnum = 8
	TunnelTypeEnumESP      TunnelTypeEnum = 9
	TunnelTypeEnumGRE      TunnelTypeEnum = 10
	TunnelTypeEnumDVS      TunnelTypeEnum = 11
	TunnelTypeEnumIPInIP   TunnelTypeEnum = 12
	TunnelTypeEnumVLAN     TunnelTypeEnum = 13
)

// String returns the standard name for the tunnel type value.
func (e TunnelTypeEnum) String() string {
	switch e {
	case TunnelTypeEnumPPTP:
		return "PPTP"
	case TunnelTypeEnumL2F:
		return "L2F"
	case TunnelTypeEnumL2TP:
		return "L2TP"
	case TunnelTypeEnumATMP:
		return "ATMP"
	case TunnelTypeEnumVTP:
		return "VTP"
	case TunnelTypeEnumAH:
		return "AH"
	case TunnelTypeEnumIPIP:
		return "IP-IP"
	case TunnelTypeEnumMinIPIP:
		return "MIN-IP-IP"
	case TunnelTypeEnumESP:
		return "ESP"
	case TunnelTypeEnumGRE:
		return "GRE"
	case TunnelTypeEnumDVS:
		return "DVS"
	case TunnelTypeEnumIPInIP:
		return "IP-in-IP"
	case TunnelTypeEnumVLAN:
		return "VLAN"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

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

// String returns the standard name for the tunnel medium type value.
func (e TunnelMediumTypeEnum) String() string {
	switch e {
	case TunnelMediumTypeEnumIPv4:
		return "IPv4"
	case TunnelMediumTypeEnumIPv6:
		return "IPv6"
	case TunnelMediumTypeEnumNSAP:
		return "NSAP"
	case TunnelMediumTypeEnumHDLC:
		return "HDLC"
	case TunnelMediumTypeEnumBBN1822:
		return "BBN-1822"
	case TunnelMediumTypeEnum802:
		return "802"
	case TunnelMediumTypeEnumE163:
		return "E.163"
	case TunnelMediumTypeEnumE164:
		return "E.164"
	case TunnelMediumTypeEnumF69:
		return "F.69"
	case TunnelMediumTypeEnumX121:
		return "X.121"
	case TunnelMediumTypeEnumIPX:
		return "IPX"
	case TunnelMediumTypeEnumAppletalk:
		return "Appletalk"
	case TunnelMediumTypeEnumDecnetIV:
		return "Decnet-IV"
	case TunnelMediumTypeEnumBanyanVines:
		return "Banyan-Vines"
	case TunnelMediumTypeEnumE164NSAP:
		return "E.164-NSAP"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

// AcctTerminateCauseEnum is the decoded form of Acct-Terminate-Cause.
type AcctTerminateCauseEnum uint32

const (
	AcctTerminateCauseEnumUserRequest       AcctTerminateCauseEnum = 1
	AcctTerminateCauseEnumLostCarrier       AcctTerminateCauseEnum = 2
	AcctTerminateCauseEnumLostService       AcctTerminateCauseEnum = 3
	AcctTerminateCauseEnumIdleTimeout       AcctTerminateCauseEnum = 4
	AcctTerminateCauseEnumSessionTimeout    AcctTerminateCauseEnum = 5
	AcctTerminateCauseEnumAdminReset        AcctTerminateCauseEnum = 6
	AcctTerminateCauseEnumAdminReboot       AcctTerminateCauseEnum = 7
	AcctTerminateCauseEnumPortError         AcctTerminateCauseEnum = 8
	AcctTerminateCauseEnumNASError          AcctTerminateCauseEnum = 9
	AcctTerminateCauseEnumNASRequest        AcctTerminateCauseEnum = 10
	AcctTerminateCauseEnumNASReboot         AcctTerminateCauseEnum = 11
	AcctTerminateCauseEnumPortUnneeded      AcctTerminateCauseEnum = 12
	AcctTerminateCauseEnumPortPreempted     AcctTerminateCauseEnum = 13
	AcctTerminateCauseEnumPortSuspended     AcctTerminateCauseEnum = 14
	AcctTerminateCauseEnumServiceUnavailable AcctTerminateCauseEnum = 15
	AcctTerminateCauseEnumCallback          AcctTerminateCauseEnum = 16
	AcctTerminateCauseEnumUserError         AcctTerminateCauseEnum = 17
	AcctTerminateCauseEnumHostRequest       AcctTerminateCauseEnum = 18
)

// String returns the standard name for the accounting terminate cause value.
func (e AcctTerminateCauseEnum) String() string {
	switch e {
	case AcctTerminateCauseEnumUserRequest:
		return "UserRequest"
	case AcctTerminateCauseEnumLostCarrier:
		return "LostCarrier"
	case AcctTerminateCauseEnumLostService:
		return "LostService"
	case AcctTerminateCauseEnumIdleTimeout:
		return "IdleTimeout"
	case AcctTerminateCauseEnumSessionTimeout:
		return "SessionTimeout"
	case AcctTerminateCauseEnumAdminReset:
		return "AdminReset"
	case AcctTerminateCauseEnumAdminReboot:
		return "AdminReboot"
	case AcctTerminateCauseEnumPortError:
		return "PortError"
	case AcctTerminateCauseEnumNASError:
		return "NAS-Error"
	case AcctTerminateCauseEnumNASRequest:
		return "NAS-Request"
	case AcctTerminateCauseEnumNASReboot:
		return "NAS-Reboot"
	case AcctTerminateCauseEnumPortUnneeded:
		return "PortUnneeded"
	case AcctTerminateCauseEnumPortPreempted:
		return "PortPreempted"
	case AcctTerminateCauseEnumPortSuspended:
		return "PortSuspended"
	case AcctTerminateCauseEnumServiceUnavailable:
		return "ServiceUnavailable"
	case AcctTerminateCauseEnumCallback:
		return "Callback"
	case AcctTerminateCauseEnumUserError:
		return "UserError"
	case AcctTerminateCauseEnumHostRequest:
		return "HostRequest"
	}
	return "unknow code " + strconv.Itoa(int(e))
}
