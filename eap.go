package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type EapCode uint8

const (
	EapCodeRequest  EapCode = 1
	EapCodeResponse EapCode = 2
	EapCodeSuccess  EapCode = 3
	EapCodeFailure  EapCode = 4
)

func (c EapCode) String() string {
	switch c {
	case EapCodeRequest:
		return "Request"
	case EapCodeResponse:
		return "Response"
	case EapCodeSuccess:
		return "Success"
	case EapCodeFailure:
		return "Failure"
	default:
		return "unknow EapCode " + strconv.Itoa(int(c))
	}
}

type EapType uint8

const (
	EapTypeIdentity         EapType = 1
	EapTypeNotification     EapType = 2
	EapTypeNak              EapType = 3 //Response only
	EapTypeMd5Challenge     EapType = 4
	EapTypeOneTimePassword  EapType = 5 //otp
	EapTypeGenericTokenCard EapType = 6 //gtc
	EapTypeMSCHAPV2         EapType = 26
	EapTypeExpandedTypes    EapType = 254
	EapTypeExperimentalUse  EapType = 255
)

func (c EapType) String() string {
	switch c {
	case EapTypeIdentity:
		return "Identity"
	case EapTypeNotification:
		return "Notification"
	case EapTypeNak:
		return "Nak"
	case EapTypeMd5Challenge:
		return "Md5Challenge"
	case EapTypeOneTimePassword:
		return "OneTimePassword"
	case EapTypeGenericTokenCard:
		return "GenericTokenCard"
	case EapTypeMSCHAPV2:
		return "MSCHAPV2"
	case EapTypeExpandedTypes:
		return "ExpandedTypes"
	case EapTypeExperimentalUse:
		return "ExperimentalUse"
	default:
		return "unknow EapType " + strconv.Itoa(int(c))
	}
}

type EapPacket struct {
	Code       EapCode
	Identifier uint8
	Type       EapType
	Data       []byte
}

func (a *EapPacket) String() string {
	if a.Code == EapCodeSuccess || a.Code == EapCodeFailure {
		return fmt.Sprintf("Eap Code:%s id:%d", a.Code.String(), a.Identifier)
	}
	return fmt.Sprintf("Eap Code:%s id:%d Type:%s Data:[%s]", a.Code.String(), a.Identifier, a.Type.String(), a.valueString())
}

func (a *EapPacket) valueString() string {
	switch a.Type {
	case EapTypeIdentity:
		return fmt.Sprintf("%#v", string(a.Data)) //It should be a string, but it may be mistaken
	case EapTypeMSCHAPV2:
		mcv, err := MsChapV2PacketFromEap(a)
		if err != nil {
			return err.Error()
		}
		return mcv.String()
	}
	return fmt.Sprintf("%#v", a.Data)
}

func (a *EapPacket) Copy() *EapPacket {
	eap := *a
	eap.Data = append([]byte(nil), a.Data...)
	return &eap
}

func (a *EapPacket) Encode() (b []byte) {
	if a.Code == EapCodeSuccess || a.Code == EapCodeFailure {
		b = make([]byte, 4)
		b[0] = byte(a.Code)
		b[1] = byte(a.Identifier)
		binary.BigEndian.PutUint16(b[2:4], 4)
		return b
	}
	b = make([]byte, len(a.Data)+5)
	b[0] = byte(a.Code)
	b[1] = byte(a.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(a.Data)+5))
	b[4] = byte(a.Type)
	copy(b[5:], a.Data)
	return b
}

func (a *EapPacket) ToEAPMessage() *AVP {
	return &AVP{
		Type:  AttrEAPMessage,
		Value: a.Encode(),
	}
}

func EapDecode(b []byte) (eap *EapPacket, err error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small")
	}
	length := binary.BigEndian.Uint16(b[2:4])
	if length < 4 || len(b) < int(length) {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small")
	}
	code := EapCode(b[0])
	eap = &EapPacket{
		Code:       code,
		Identifier: uint8(b[1]),
	}
	// EAP-Success and EAP-Failure have no Type or Data fields (RFC 3748 §4)
	if code == EapCodeSuccess || code == EapCodeFailure {
		return eap, nil
	}
	if length < 5 || len(b) < 5 {
		return nil, fmt.Errorf("[EapDecode] protocol error: Request/Response too small")
	}
	eap.Type = EapType(b[4])
	eap.Data = b[5:length]
	return eap, nil
}
