package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

const (
	eapHeaderLen         = 4                    // Code, Identifier, Length
	eapTypeHeaderLen     = 5                    // header + Type
	eapExpandedHeaderLen = eapTypeHeaderLen + 7 // + Vendor-Id(3) + Vendor-Type(4)
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
	return a.format(a.valueString())
}

func (a *EapPacket) format(data string) string {
	return fmt.Sprintf("Eap Code:%s id:%d Type:%s Data:[%s]", a.Code.String(), a.Identifier, a.Type.String(), data)
}

// stringMasked is String for StringMasked: only Identity, Notification and Nak
// data is shown, other types' data (e.g. an MS-CHAPv2 or MD5 response, a GTC
// password) as its length, with the MS-CHAPv2 opcode.
func (a *EapPacket) stringMasked() string {
	switch {
	case a.Code == EapCodeSuccess || a.Code == EapCodeFailure,
		a.Type == EapTypeIdentity || a.Type == EapTypeNotification || a.Type == EapTypeNak:
		return a.String()
	}
	data := strconv.Itoa(len(a.Data)) + " bytes"
	if a.Type == EapTypeMSCHAPV2 && len(a.Data) > 0 {
		data = "OpCode:" + MsChapV2OpCode(a.Data[0]).String() + " " + data
	}
	return a.format(data)
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
		b = make([]byte, eapHeaderLen)
		b[0] = byte(a.Code)
		b[1] = byte(a.Identifier)
		binary.BigEndian.PutUint16(b[2:4], eapHeaderLen)
		return b
	}
	b = make([]byte, len(a.Data)+eapTypeHeaderLen)
	b[0] = byte(a.Code)
	b[1] = byte(a.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[4] = byte(a.Type)
	copy(b[eapTypeHeaderLen:], a.Data)
	return b
}

// ToEAPMessage returns a single EAP-Message AVP; packets over 253 bytes need ToEAPMessages.
func (a *EapPacket) ToEAPMessage() *AVP {
	return &AVP{
		Type:  AttrEAPMessage,
		Value: a.Encode(),
	}
}

// ToEAPMessages splits the encoded packet into EAP-Message AVPs of at most 253 bytes (RFC 3579 §3.1).
func (a *EapPacket) ToEAPMessages() []AVP {
	b := a.Encode()
	avps := make([]AVP, 0, (len(b)+maxAVPValueLen-1)/maxAVPValueLen)
	for len(b) > 0 {
		n := min(len(b), maxAVPValueLen)
		avps = append(avps, AVP{Type: AttrEAPMessage, Value: b[:n:n]})
		b = b[n:]
	}
	return avps
}

// EapDecode decodes an EAP packet; bytes past the Length field are ignored (RFC 3748 §4).
// Data aliases b.
func EapDecode(b []byte) (eap *EapPacket, err error) {
	if len(b) < eapHeaderLen {
		return nil, fmt.Errorf("[EapDecode] protocol error: %d bytes, need %d", len(b), eapHeaderLen)
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < eapHeaderLen {
		return nil, fmt.Errorf("[EapDecode] protocol error: Length %d below header size", length)
	}
	if len(b) < length {
		return nil, fmt.Errorf("[EapDecode] protocol error: Length %d exceeds %d bytes", length, len(b))
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
	if length < eapTypeHeaderLen {
		return nil, fmt.Errorf("[EapDecode] protocol error: Request/Response too small")
	}
	eap.Type = EapType(b[4])
	if eap.Type == EapTypeExpandedTypes && length < eapExpandedHeaderLen {
		return nil, fmt.Errorf("[EapDecode] protocol error: Expanded Type too small")
	}
	eap.Data = b[eapTypeHeaderLen:length]
	return eap, nil
}
