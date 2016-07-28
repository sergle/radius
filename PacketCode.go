package radius

import (
	"strconv"
)

type PacketCode uint8

const (
	AccessRequest      PacketCode = 1
	AccessAccept       PacketCode = 2
	AccessReject       PacketCode = 3
	AccountingRequest  PacketCode = 4
	AccountingResponse PacketCode = 5
	AccessChallenge    PacketCode = 11
	StatusServer       PacketCode = 12 //(experimental)
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

func (p PacketCode) String() string {
	name, ok := packetCodeName[p]
	if ok {
		return name
	}

	return "unknown packet code " + strconv.Itoa(int(p))
}

func (p PacketCode) IsRequest() bool {
	if p == AccessRequest || p == AccountingRequest || p == DisconnectRequest || p == CoARequest {
		return true
	}
	return false
}

func (p PacketCode) IsAccess() bool {
	if p == AccessRequest || p == AccessAccept || p == AccessReject || p == AccessChallenge {
		return true
	}
	return false
}
