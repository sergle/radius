package radius

import (
	"strconv"
)

// PacketCode is the RADIUS packet Code field.
type PacketCode uint8

const (
	AccessRequest      PacketCode = 1
	AccessAccept       PacketCode = 2
	AccessReject       PacketCode = 3
	AccountingRequest  PacketCode = 4
	AccountingResponse PacketCode = 5
	AccessChallenge    PacketCode = 11
	StatusServer       PacketCode = 12 // RFC 5997
	StatusClient       PacketCode = 13 //(experimental)
	DisconnectRequest  PacketCode = 40
	DisconnectAccept   PacketCode = 41
	DisconnectReject   PacketCode = 42
	CoARequest         PacketCode = 43
	CoAAccept          PacketCode = 44
	CoAReject          PacketCode = 45
	Reserved           PacketCode = 255
)

var packetCodeName = map[PacketCode]string{
	AccessRequest:      "AccessRequest",
	AccessAccept:       "AccessAccept",
	AccessReject:       "AccessReject",
	AccountingRequest:  "AccountingRequest",
	AccountingResponse: "AccountingResponse",
	AccessChallenge:    "AccessChallenge",
	StatusServer:       "StatusServer",
	StatusClient:       "StatusClient",
	DisconnectRequest:  "DisconnectRequest",
	DisconnectAccept:   "DisconnectAccept",
	DisconnectReject:   "DisconnectReject",
	CoARequest:         "CoARequest",
	CoAAccept:          "CoAAccept",
	CoAReject:          "CoAReject",
	Reserved:           "Reserved",
}

// String returns the canonical name of the packet code.
func (pc PacketCode) String() string {
	name, ok := packetCodeName[pc]
	if ok {
		return name
	}

	return "unknown packet code " + strconv.Itoa(int(pc))
}

// IsRequest reports whether the code is a request (as opposed to a reply).
// Requests and replies compute their Authenticator and Message-Authenticator differently.
func (pc PacketCode) IsRequest() bool {
	switch pc {
	case AccessRequest, AccountingRequest, DisconnectRequest, CoARequest, StatusServer:
		return true
	}
	return false
}

// hasRandomAuthenticator reports whether the code's Request Authenticator is random.
func (pc PacketCode) hasRandomAuthenticator() bool {
	switch pc {
	case AccessRequest, StatusServer:
		return true
	}
	return false
}

// hasMessageAuthenticator reports whether the code is signed with Message-Authenticator on encode.
func (pc PacketCode) hasMessageAuthenticator() bool {
	return pc.IsAccess() || pc == StatusServer
}

// IsAccess reports whether the code is in the Access-* family.
func (pc PacketCode) IsAccess() bool {
	switch pc {
	case AccessRequest, AccessAccept, AccessReject, AccessChallenge:
		return true
	}
	return false
}
