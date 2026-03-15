package radius

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"sync"
)

var ErrMessageAuthenticatorCheckFail = fmt.Errorf("RADIUS Message-Authenticator verification failed")
var ErrAuthenticatorCheckFail = fmt.Errorf("RADIUS Authenticator verification failed")

type Packet struct {
	Secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [16]byte
	AVPs          []AVP
	RawAVPs       []byte // Unparsed attributes for lazy decoding
	ClientAddr    string
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return &Packet{
			AVPs: make([]AVP, 0, 10),
		}
	},
}

// Release returns the packet to the pool.
// The packet should not be used after being released.
func (p *Packet) Release() {
	if p == nil {
		return
	}
	p.Reset()
	packetPool.Put(p)
}

// Reset clears the packet state for reuse.
func (p *Packet) Reset() {
	p.Secret = ""
	p.Code = 0
	p.Identifier = 0
	p.Authenticator = [16]byte{}
	p.AVPs = p.AVPs[:0]
	p.RawAVPs = nil
	p.ClientAddr = ""
}

func (p *Packet) Copy() *Packet {
	outP := &Packet{
		Secret:        p.Secret,
		Code:          p.Code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator, // This should be a copy
	}
	outP.AVPs = make([]AVP, len(p.AVPs))
	for i := range p.AVPs {
		outP.AVPs[i] = p.AVPs[i].Copy()
	}
	return outP
}

// This method guarantees that the contents of the package are not modified
func (p *Packet) Encode() (b []byte, err error) {
	b = make([]byte, 4096)
	n, err := p.EncodeTo(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// EncodeTo encodes the packet into the provided buffer.
func (p *Packet) EncodeTo(b []byte) (n int, err error) {
	if p.Code.IsAccess() {
		// append Message-Authenticator AVP
		p.SetAVP(AVP{
			Type:  AttrMessageAuthenticator,
			Value: make([]byte, 16),
		})

		if p.Code == AccessRequest && p.Authenticator[0] == 0 {
			_, err := rand.Read(p.Authenticator[:])
			if err != nil {
				return 0, err
			}
		}
	}

	// When the password request recalculation
	n, err = p.encodeNoHashTo(b)
	if err != nil {
		return
	}

	if p.Code.IsAccess() {
		//Calculation Message-Authenticator it is placed in the rearmost
		hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
		hasher.Write(b[:n])
		copy(b[n-16:n], hasher.Sum(nil))
		// update value in packet structure
		avp := p.GetAVP(AttrMessageAuthenticator)
		copy(avp.Value, b[n-16:n])
	}

	// fix up the authenticator
	// handle request and response stuff.
	// here only handle response part.
	switch p.Code {
	case AccessRequest:
	case DisconnectRequest, DisconnectAccept, DisconnectReject:
		fallthrough
	case CoARequest, CoAAccept, CoAReject:
		fallthrough
	case AccessAccept, AccessReject, AccessChallenge, AccountingRequest, AccountingResponse:
		hasher := crypto.Hash(crypto.MD5).New()
		hasher.Write(b[:n])
		hasher.Write([]byte(p.Secret))
		copy(p.Authenticator[:], hasher.Sum(nil))
		copy(b[4:20], p.Authenticator[:])
	default:
		return 0, fmt.Errorf("not handle p.Code %d", p.Code)
	}

	return n, nil
}

func (p *Packet) encodeNoHash() (b []byte, err error) {
	b = make([]byte, 4096)
	n, err := p.encodeNoHashTo(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func (p *Packet) encodeNoHashTo(b []byte) (n int, err error) {
	if len(b) < 20 {
		return 0, errors.New("buffer too small")
	}
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20

	if len(p.AVPs) > 0 {
		bb := b[20:]
		for i := range p.AVPs {
			n, err := p.AVPs[i].Encode(bb)
			written += n
			if err != nil {
				return 0, err
			}
			bb = bb[n:]
		}
	} else if len(p.RawAVPs) > 0 {
		if len(b) < 20+len(p.RawAVPs) {
			return 0, errors.New("buffer too small")
		}
		copy(b[20:], p.RawAVPs)
		written += len(p.RawAVPs)
	}

	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	return written, nil
}

func (p *Packet) HasAVP(attrType AttributeType) bool {
	if len(p.AVPs) > 0 {
		for i := range p.AVPs {
			if p.AVPs[i].Type == attrType {
				return true
			}
		}
		return false
	}
	b := p.RawAVPs
	for len(b) >= 2 {
		length := uint8(b[1])
		if int(length) > len(b) || length < 2 {
			return false
		}
		if AttributeType(b[0]) == attrType {
			return true
		}
		b = b[length:]
	}
	return false
}

// get one avp
func (p *Packet) GetAVP(attrType AttributeType) *AVP {
	if len(p.AVPs) > 0 {
		for i := range p.AVPs {
			if p.AVPs[i].Type == attrType {
				return &p.AVPs[i]
			}
		}
		return nil
	}
	b := p.RawAVPs
	for len(b) >= 2 {
		length := uint8(b[1])
		if int(length) > len(b) || length < 2 {
			return nil
		}
		if AttributeType(b[0]) == attrType {
			return &AVP{Type: attrType, Value: b[2:length]}
		}
		b = b[length:]
	}
	return nil
}

func (p *Packet) EachAVP(fn func(a AVP) bool) {
	if len(p.AVPs) > 0 {
		for i := range p.AVPs {
			if !fn(p.AVPs[i]) {
				return
			}
		}
		return
	}

	b := p.RawAVPs
	for len(b) >= 2 {
		length := uint8(b[1])
		if int(length) > len(b) || length < 2 {
			return
		}
		if !fn(AVP{Type: AttributeType(b[0]), Value: b[2:length]}) {
			return
		}
		b = b[length:]
	}
}

// set one avp,remove all other same type
func (p *Packet) SetAVP(avp AVP) {
	p.DeleteOneType(avp.Type)
	p.AddAVP(avp)
}

func (p *Packet) AddAVP(avp AVP) {
	p.AVPs = append(p.AVPs, avp)
}

func (p *Packet) AddVSA(vsa VSA) {
	p.AddAVP(vsa.ToAVP())
}

// Delete one AVP
func (p *Packet) DeleteAVP(avp *AVP) {
	for i := range p.AVPs {
		if &(p.AVPs[i]) == avp {
			for j := i; j < len(p.AVPs)-1; j++ {
				p.AVPs[j] = p.AVPs[j+1]
			}
			p.AVPs = p.AVPs[:len(p.AVPs)-1]
			break
		}
	}
	return
}

// delete all avps with this type
func (p *Packet) DeleteOneType(attrType AttributeType) {
	for i := 0; i < len(p.AVPs); i++ {
		if p.AVPs[i].Type == attrType {
			for j := i; j < len(p.AVPs)-1; j++ {
				p.AVPs[j] = p.AVPs[j+1]
			}
			p.AVPs = p.AVPs[:len(p.AVPs)-1]
			i--
			break
		}
	}
	return
}

func Request(code PacketCode, secret string) *Packet {
	packet := new(Packet)
	packet.Secret = secret
	packet.Code = code
	packet.Identifier = uint8(mrand.Int31n(255))

	if code == AccessRequest {
		// generate new - will be used to encode password
		rand.Read(packet.Authenticator[:])
	}

	return packet
}

func (p *Packet) Reply() *Packet {
	pac := new(Packet)
	pac.Authenticator = p.Authenticator
	pac.Identifier = p.Identifier
	pac.Secret = p.Secret
	return pac
}

func (p *Packet) Send(c net.PacketConn, addr net.Addr) error {
	buf, err := p.Encode()
	if err != nil {
		return err
	}

	_, err = c.WriteTo(buf, addr)
	return err
}

// kept for backward compatibility, use DecodeRequest(...)
func DecodePacket(secret string, buf []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, nil)
}

func DecodeRequest(secret string, buf []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, nil)
}

func DecodeReply(secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, request_auth)
}

func DecodeRequestPooled(secret string, buf []byte) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, nil)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

func DecodeReplyPooled(secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, request_auth)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

func DecodeRequestLazy(secret string, buf []byte) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, nil)
}

func DecodeReplyLazy(secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, request_auth)
}

// decode request/reply
func decodePacket(Secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	err = decodePacketTo(p, Secret, buf, request_auth)
	return p, err
}

func decodePacketTo(p *Packet, Secret string, buf []byte, request_auth []byte) error {
	err := decodePacketHeaderTo(p, Secret, buf, request_auth)
	if err != nil {
		return err
	}

	//read attributes
	b := buf[20:]
	for len(b) >= 2 {
		length := uint8(b[1])
		if int(length) > len(b) || length < 2 {
			return errors.New("invalid length")
		}
		attr := AVP{}
		attr.Type = AttributeType(b[0])
		attr.Value = b[2:length]
		p.AVPs = append(p.AVPs, attr)
		b = b[length:]
	}

	//Verify the Message-Authenticator and verify that the algorithm here is correct through testing
	err = p.checkMessageAuthenticator(request_auth)
	if err != nil {
		return err
	}
	return nil
}

func decodePacketLazy(Secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	p, err = decodePacketHeader(Secret, buf, request_auth)
	if err != nil {
		return p, err
	}
	p.RawAVPs = buf[20:]

	// Verify the Message-Authenticator
	// Note: Message-Authenticator verification requires walking the attributes
	// if we want to be fully lazy, we could defer this, but it's safer to check now.
	err = p.checkMessageAuthenticator(request_auth)
	if err != nil {
		return p, err
	}
	return p, nil
}

func decodePacketHeader(Secret string, buf []byte, request_auth []byte) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	err = decodePacketHeaderTo(p, Secret, buf, request_auth)
	return p, err
}

func decodePacketHeaderTo(p *Packet, Secret string, buf []byte, request_auth []byte) error {
	if len(buf) < 20 {
		return errors.New("invalid length")
	}

	p.Secret = Secret
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:20])

	if err := p.checkAuthenticator(buf, request_auth); err != nil {
		return err
	}
	return nil
}

func (p *Packet) checkAuthenticator(buf []byte, request_auth []byte) (err error) {
	if p.Code == AccessRequest {
		// it has random authenticator, do not verify
		return nil
	}

	hasher := crypto.Hash(crypto.MD5).New()
	hasher.Write(buf[0:4])
	if p.Code.IsRequest() {
		// Accounting, PoD, CoA
		hasher.Write(make([]byte, 16))
	} else {
		// value from request packet
		hasher.Write(request_auth)
	}
	hasher.Write(buf[20:])
	hasher.Write([]byte(p.Secret))
	expected := hasher.Sum(nil)
	if bytes.Compare(expected, p.Authenticator[:]) != 0 {
		return ErrAuthenticatorCheckFail
	}
	// ok
	return nil
}

// check value of Message-Authenticator AVP
func (p *Packet) checkMessageAuthenticator(request_auth []byte) (err error) {
	avp := p.GetAVP(AttrMessageAuthenticator)
	if avp == nil {
		return nil
	}
	origValue := make([]byte, 16)
	copy(origValue, avp.Value)
	// restore after validation
	defer func() { copy(avp.Value, origValue) }()

	if !p.Code.IsRequest() {
		// orig authenticator from request to verify reply
		p_auth := make([]byte, 16)
		copy(p_auth, p.Authenticator[:])
		defer func() { copy(p.Authenticator[:], p_auth) }()
		copy(p.Authenticator[:], request_auth)
	}

	avp.Value = make([]byte, 16)

	// TODO do not encode/decode, verify agains buf[] on packet
	// For lazy packets, we must use encodeNoHash which now handles RawAVPs
	// We use a stack buffer to avoid allocation
	var buf [4096]byte
	n, err := p.encodeNoHashTo(buf[:])
	if err != nil {
		return err
	}
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(buf[:n])
	if !hmac.Equal(hasher.Sum(nil), origValue) {
		return ErrMessageAuthenticatorCheckFail
	}
	return nil
}

func (p *Packet) String() string {
	s := "From: " + p.ClientAddr + "\n" +
		"Code: " + p.Code.String() + "\n" +
		"Identifier: " + strconv.Itoa(int(p.Identifier)) + "\n" +
		"Authenticator: " + fmt.Sprintf("%#v", p.Authenticator) + "\n"
	for _, avp := range p.AVPs {
		s += avp.StringWithPacket(p) + "\n"
	}
	return s
}

func (p *Packet) GetUsername() (username string) {
	avp := p.GetAVP(AttrUserName)
	if avp == nil {
		return ""
	}
	val := avp.Decode(p)
	if s, ok := val.(string); ok {
		return s
	}
	if b, ok := val.([]byte); ok {
		return string(b)
	}
	return ""
}
func (p *Packet) GetPassword() (password string) {
	avp := p.GetAVP(AttrUserPassword)
	if avp == nil {
		return ""
	}
	val := avp.Decode(p)
	if s, ok := val.(string); ok {
		return s
	}
	if _, ok := val.([]byte); ok {
		// If no dictionary is loaded, we can't automatically decrypt via Decode.
		// However, we can use the avpPassword handler directly.
		return avpPassword.Value(p, *avp).(string)
	}
	return ""
}
func (p *Packet) AddPassword(password string) {
	p.SetAVP(AVP{
		Type:  AttrUserPassword,
		Value: avpPassword.Encode(password, p.Secret, p.Authenticator[:]),
	})
}

func (p *Packet) GetNasIpAddress() (ip net.IP) {
	avp := p.GetAVP(AttrNASIPAddress)
	if avp == nil {
		return nil
	}
	val := avp.Decode(p)
	if ip, ok := val.(net.IP); ok {
		return ip
	}
	if b, ok := val.([]byte); ok {
		return net.IP(b)
	}
	return nil
}

func (p *Packet) GetAcctStatusType() AcctStatusTypeEnum {
	avp := p.GetAVP(AttrAcctStatusType)
	if avp == nil {
		return AcctStatusTypeEnum(0)
	}
	val := avp.Decode(p)
	if v, ok := val.(AcctStatusTypeEnum); ok {
		return v
	}
	if i, ok := val.(uint32); ok {
		return AcctStatusTypeEnum(i)
	}
	if b, ok := val.([]byte); ok && len(b) == 4 {
		return AcctStatusTypeEnum(binary.BigEndian.Uint32(b))
	}
	return AcctStatusTypeEnum(0)
}

func (p *Packet) GetAcctSessionId() string {
	avp := p.GetAVP(AttrAcctSessionId)
	if avp == nil {
		return ""
	}
	val := avp.Decode(p)
	if s, ok := val.(string); ok {
		return s
	}
	if b, ok := val.([]byte); ok {
		return string(b)
	}
	return ""
}

func (p *Packet) GetAcctTotalOutputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AttrAcctOutputOctets)
	if avp != nil {
		val := avp.Decode(p)
		if i, ok := val.(uint32); ok {
			out += uint64(i)
		} else if b, ok := val.([]byte); ok && len(b) == 4 {
			out += uint64(binary.BigEndian.Uint32(b))
		}
	}
	avp = p.GetAVP(AttrAcctOutputGigawords)
	if avp != nil {
		val := avp.Decode(p)
		if i, ok := val.(uint32); ok {
			out += uint64(i) << 32
		} else if b, ok := val.([]byte); ok && len(b) == 4 {
			out += uint64(binary.BigEndian.Uint32(b)) << 32
		}
	}
	return out
}

func (p *Packet) GetAcctTotalInputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AttrAcctInputOctets)
	if avp != nil {
		val := avp.Decode(p)
		if i, ok := val.(uint32); ok {
			out += uint64(i)
		} else if b, ok := val.([]byte); ok && len(b) == 4 {
			out += uint64(binary.BigEndian.Uint32(b))
		}
	}
	avp = p.GetAVP(AttrAcctInputGigawords)
	if avp != nil {
		val := avp.Decode(p)
		if i, ok := val.(uint32); ok {
			out += uint64(i) << 32
		} else if b, ok := val.([]byte); ok && len(b) == 4 {
			out += uint64(binary.BigEndian.Uint32(b)) << 32
		}
	}
	return out
}

// it is ike_id in strongswan client
func (p *Packet) GetNASPort() uint32 {
	avp := p.GetAVP(AttrNASPort)
	if avp == nil {
		return 0
	}
	val := avp.Decode(p)
	if i, ok := val.(uint32); ok {
		return i
	}
	if b, ok := val.([]byte); ok && len(b) == 4 {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (p *Packet) GetNASIdentifier() string {
	avp := p.GetAVP(AttrNASIdentifier)
	if avp == nil {
		return ""
	}
	val := avp.Decode(p)
	if s, ok := val.(string); ok {
		return s
	}
	if b, ok := val.([]byte); ok {
		return string(b)
	}
	return ""
}

func (p *Packet) GetEAPMessage() *EapPacket {
	avp := p.GetAVP(AttrEAPMessage)
	if avp == nil {
		return nil
	}
	val := avp.Decode(p)
	if eap, ok := val.(*EapPacket); ok {
		return eap
	}
	return nil
}

func (p *Packet) GetNASPortType() NASPortTypeEnum {
	avp := p.GetAVP(AttrNASPortType)
	if avp == nil {
		return NASPortTypeEnum(0)
	}
	val := avp.Decode(p)
	if v, ok := val.(NASPortTypeEnum); ok {
		return v
	}
	if i, ok := val.(uint32); ok {
		return NASPortTypeEnum(i)
	}
	if b, ok := val.([]byte); ok && len(b) == 4 {
		return NASPortTypeEnum(binary.BigEndian.Uint32(b))
	}
	return NASPortTypeEnum(0)
}

func (p *Packet) GetServiceType() ServiceTypeEnum {
	avp := p.GetAVP(AttrServiceType)
	if avp == nil {
		return ServiceTypeEnum(0)
	}
	val := avp.Decode(p)
	if v, ok := val.(ServiceTypeEnum); ok {
		return v
	}
	if i, ok := val.(uint32); ok {
		return ServiceTypeEnum(i)
	}
	if b, ok := val.([]byte); ok && len(b) == 4 {
		return ServiceTypeEnum(binary.BigEndian.Uint32(b))
	}
	return ServiceTypeEnum(0)
}
