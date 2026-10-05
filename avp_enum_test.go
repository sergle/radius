package radius

import (
	"fmt"
	"testing"
)

// enumCase pairs an enum value with its expected String().
type enumCase struct {
	e    fmt.Stringer
	want string
}

const unknownEnumPrefix = "unknown code "

func TestEnumString(t *testing.T) {
	cases := []enumCase{
		{AcctStatusTypeEnumStart, "Start"},
		{AcctStatusTypeEnumStop, "Stop"},
		{AcctStatusTypeEnumInterimUpdate, "InterimUpdate"},
		{AcctStatusTypeEnumAccountingOn, "AccountingOn"},
		{AcctStatusTypeEnumAccountingOff, "AccountingOff"},
		{AcctStatusTypeEnumTunnelStart, "Tunnel-Start"},
		{AcctStatusTypeEnumTunnelStop, "Tunnel-Stop"},
		{AcctStatusTypeEnumTunnelReject, "Tunnel-Reject"},
		{AcctStatusTypeEnumTunnelLinkStart, "Tunnel-Link-Start"},
		{AcctStatusTypeEnumTunnelLinkStop, "Tunnel-Link-Stop"},
		{AcctStatusTypeEnumTunnelLinkReject, "Tunnel-Link-Reject"},
		{AcctStatusTypeEnum(99), unknownEnumPrefix + "99"},

		{NASPortTypeEnumAsync, "Async"},
		{NASPortTypeEnumSync, "Sync"},
		{NASPortTypeEnumISDNSync, "ISDNSync"},
		{NASPortTypeEnumISDNSyncV120, "ISDNSyncV120"},
		{NASPortTypeEnumISDNSyncV110, "ISDNSyncV110"},
		{NASPortTypeEnumVirtual, "Virtual"},
		{NASPortTypeEnumPIAFS, "PIAFS"},
		{NASPortTypeEnumHDLCClearChannel, "HDLCClearChannel"},
		{NASPortTypeEnumEthernet, "Ethernet"},
		{NASPortTypeEnumxDSL, "xDSL"},
		{NASPortTypeEnumCable, "Cable"},
		{NASPortTypeEnumWirelessOther, "Wireless-Other"},
		{NASPortTypeEnumWireless80211, "Wireless-IEEE-802.11"},
		{NASPortTypeEnumTokenRing, "Token-Ring"},
		{NASPortTypeEnumFDDI, "FDDI"},
		{NASPortTypeEnum(99), unknownEnumPrefix + "99"},

		{ServiceTypeEnumLogin, "Login"},
		{ServiceTypeEnumFramed, "Framed"},
		{ServiceTypeEnumCallbackLogin, "CallbackLogin"},
		{ServiceTypeEnumCallbackFramed, "CallbackFramed"},
		{ServiceTypeEnumOutbound, "Outbound"},
		{ServiceTypeEnumAdministrative, "Administrative"},
		{ServiceTypeEnumNASPrompt, "NAS-Prompt"},
		{ServiceTypeEnumAuthenticateOnly, "Authenticate-Only"},
		{ServiceTypeEnumCallCheck, "Call-Check"},
		{ServiceTypeEnum(0), unknownEnumPrefix + "0"},

		{PromptEnumNoEcho, "No-Echo"},
		{PromptEnumEcho, "Echo"},
		{PromptEnum(2), unknownEnumPrefix + "2"},

		{TunnelTypeEnumPPTP, "PPTP"},
		{TunnelTypeEnumL2F, "L2F"},
		{TunnelTypeEnumL2TP, "L2TP"},
		{TunnelTypeEnumATMP, "ATMP"},
		{TunnelTypeEnumVTP, "VTP"},
		{TunnelTypeEnumAH, "AH"},
		{TunnelTypeEnumIPIP, "IP-IP"},
		{TunnelTypeEnumMinIPIP, "MIN-IP-IP"},
		{TunnelTypeEnumESP, "ESP"},
		{TunnelTypeEnumGRE, "GRE"},
		{TunnelTypeEnumDVS, "DVS"},
		{TunnelTypeEnumIPInIP, "IP-in-IP"},
		{TunnelTypeEnumVLAN, "VLAN"},
		{TunnelTypeEnum(0), unknownEnumPrefix + "0"},

		{TunnelMediumTypeEnumIPv4, "IPv4"},
		{TunnelMediumTypeEnumIPv6, "IPv6"},
		{TunnelMediumTypeEnumNSAP, "NSAP"},
		{TunnelMediumTypeEnumHDLC, "HDLC"},
		{TunnelMediumTypeEnumBBN1822, "BBN-1822"},
		{TunnelMediumTypeEnum802, "802"},
		{TunnelMediumTypeEnumE163, "E.163"},
		{TunnelMediumTypeEnumE164, "E.164"},
		{TunnelMediumTypeEnumF69, "F.69"},
		{TunnelMediumTypeEnumX121, "X.121"},
		{TunnelMediumTypeEnumIPX, "IPX"},
		{TunnelMediumTypeEnumAppletalk, "Appletalk"},
		{TunnelMediumTypeEnumDecnetIV, "Decnet-IV"},
		{TunnelMediumTypeEnumBanyanVines, "Banyan-Vines"},
		{TunnelMediumTypeEnumE164NSAP, "E.164-NSAP"},
		{TunnelMediumTypeEnum(16), unknownEnumPrefix + "16"},

		{AcctTerminateCauseEnumUserRequest, "UserRequest"},
		{AcctTerminateCauseEnumLostCarrier, "LostCarrier"},
		{AcctTerminateCauseEnumLostService, "LostService"},
		{AcctTerminateCauseEnumIdleTimeout, "IdleTimeout"},
		{AcctTerminateCauseEnumSessionTimeout, "SessionTimeout"},
		{AcctTerminateCauseEnumAdminReset, "AdminReset"},
		{AcctTerminateCauseEnumAdminReboot, "AdminReboot"},
		{AcctTerminateCauseEnumPortError, "PortError"},
		{AcctTerminateCauseEnumNASError, "NAS-Error"},
		{AcctTerminateCauseEnumNASRequest, "NAS-Request"},
		{AcctTerminateCauseEnumNASReboot, "NAS-Reboot"},
		{AcctTerminateCauseEnumPortUnneeded, "PortUnneeded"},
		{AcctTerminateCauseEnumPortPreempted, "PortPreempted"},
		{AcctTerminateCauseEnumPortSuspended, "PortSuspended"},
		{AcctTerminateCauseEnumServiceUnavailable, "ServiceUnavailable"},
		{AcctTerminateCauseEnumCallback, "Callback"},
		{AcctTerminateCauseEnumUserError, "UserError"},
		{AcctTerminateCauseEnumHostRequest, "HostRequest"},
		{AcctTerminateCauseEnumSupplicantRestart, "SupplicantRestart"},
		{AcctTerminateCauseEnumReauthenticationFailure, "ReauthenticationFailure"},
		{AcctTerminateCauseEnumPortReinitialized, "PortReinitialized"},
		{AcctTerminateCauseEnumPortAdminDisabled, "PortAdminDisabled"},
		{AcctTerminateCauseEnum(0), unknownEnumPrefix + "0"},
	}
	for _, c := range cases {
		if got := c.e.String(); got != c.want {
			t.Errorf("%T(%d).String() = %q, want %q", c.e, c.e, got, c.want)
		}
	}
}
