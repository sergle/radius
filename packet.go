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
	"net"
	"strconv"
	"sync"
)

var ErrMessageAuthenticatorCheckFail = fmt.Errorf("RADIUS Message-Authenticator verification failed")
var ErrAuthenticatorCheckFail = fmt.Errorf("RADIUS Authenticator verification failed")
var ErrMessageAuthenticatorMissing = fmt.Errorf("RADIUS Message-Authenticator missing")

// DecodeOptions controls optional decode-time security checks.
//
// The zero value preserves historical behavior for compatibility.
type DecodeOptions struct {
	// RequireMessageAuthenticator rejects Access-* packets that do not contain
	// a Message-Authenticator attribute (RFC 3579).
	//
	// Default: false (accept packets without Message-Authenticator).
	RequireMessageAuthenticator bool
}

// Packet represents a RADIUS packet as defined by RFC 2865/RFC 2866.
//
// A Packet can be encoded for sending over the network and decoded from bytes.
// When decoding lazily, AVPs may be available via RawAVPs instead of AVPs; helper
// methods (for example GetAVP/EachAVP/HasAVP) work with either representation.
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

// Copy returns a deep copy of the packet and all currently decoded AVPs.
//
// Note: when the packet was decoded lazily (RawAVPs is set and AVPs is empty),
// Copy copies only the header fields; RawAVPs is not currently copied.
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

// Encode serializes the packet into a new byte slice.
//
// If the packet Code requires it, Encode will compute and include
// Message-Authenticator and/or update the packet Authenticator.
func (p *Packet) Encode() (b []byte, err error) {
	b = make([]byte, 4096)
	n, err := p.EncodeTo(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// EncodeTo serializes the packet into b and returns the number of bytes written.
//
// The provided buffer must be large enough for the full packet; this package
// commonly uses 4096 bytes (the RADIUS maximum packet size).
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

	// For non-Access requests (for example Accounting/CoA/Disconnect), the
	// Request Authenticator is computed using a 16-byte zero vector in the
	// hash input per RFC 2866/5176. Ensure we don't accidentally hash any
	// caller-provided authenticator value.
	if p.Code.IsRequest() && p.Code != AccessRequest {
		p.Authenticator = [16]byte{}
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

// HasAVP reports whether the packet contains at least one attribute of the given type.
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

// GetAVP returns the first attribute of the given type, or nil if not present.
//
// For lazily decoded packets, GetAVP returns a pointer to a newly allocated AVP.
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

// EachAVP iterates over attributes in the packet, calling fn for each.
//
// If fn returns false, iteration stops early.
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

// SetAVP removes all attributes of the same type and then adds avp.
func (p *Packet) SetAVP(avp AVP) {
	p.DeleteOneType(avp.Type)
	p.AddAVP(avp)
}

// AddAVP appends avp to the packet's attribute list.
func (p *Packet) AddAVP(avp AVP) {
	p.AVPs = append(p.AVPs, avp)
}

// AddVSA adds a Vendor-Specific Attribute (VSA) to the packet.
func (p *Packet) AddVSA(vsa VSA) {
	p.AddAVP(vsa.ToAVP())
}

// DeleteAVP removes the specific AVP instance from the packet, if present.
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
}

// DeleteOneType removes the first attribute with the given type from the packet.
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
}

// Request constructs a new request packet with a random Identifier.
//
// For Access-Request packets, a new request Authenticator is also generated and
// is later used for User-Password encryption and reply validation.
func Request(code PacketCode, secret string) *Packet {
	packet := new(Packet)
	packet.Secret = secret
	packet.Code = code
	// Generate a cryptographically secure random identifier.
	var id [1]byte
	if _, err := rand.Read(id[:]); err == nil {
		packet.Identifier = id[0]
	}

	if code == AccessRequest {
		// generate new - will be used to encode password
		rand.Read(packet.Authenticator[:])
	}

	return packet
}

// Reply constructs a response packet initialized with the request's
// Authenticator and Identifier.
func (p *Packet) Reply() *Packet {
	pac := new(Packet)
	pac.Authenticator = p.Authenticator
	pac.Identifier = p.Identifier
	pac.Secret = p.Secret
	return pac
}

// Send encodes the packet and writes it to addr using the provided PacketConn.
func (p *Packet) Send(c net.PacketConn, addr net.Addr) error {
	buf, err := p.Encode()
	if err != nil {
		return err
	}

	_, err = c.WriteTo(buf, addr)
	return err
}

// DecodePacket decodes a request packet from buf using the shared secret.
//
// Deprecated: kept for backward compatibility; use DecodeRequest.
func DecodePacket(secret string, buf []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, nil, nil)
}

// DecodeRequest decodes a request packet from buf using the shared secret.
func DecodeRequest(secret string, buf []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, nil, nil)
}

// DecodeRequestWithOptions decodes a request packet from buf using the shared secret
// and the provided options.
func DecodeRequestWithOptions(secret string, buf []byte, opts *DecodeOptions) (p *Packet, err error) {
	return decodePacket(secret, buf, nil, opts)
}

// DecodeReply decodes a reply packet from buf using the shared secret and
// requestAuth (the 16-byte Authenticator from the corresponding request).
func DecodeReply(secret string, buf []byte, requestAuth []byte) (p *Packet, err error) {
	return decodePacket(secret, buf, requestAuth, nil)
}

// DecodeReplyWithOptions decodes a reply packet from buf using the shared secret,
// requestAuth (the 16-byte Authenticator from the corresponding request), and options.
func DecodeReplyWithOptions(secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	return decodePacket(secret, buf, requestAuth, opts)
}

// DecodeRequestPooled decodes a request packet and returns a packet from an
// internal pool. The returned packet must be released with (*Packet).Release.
func DecodeRequestPooled(secret string, buf []byte) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, nil, nil)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeRequestPooledWithOptions is like DecodeRequestPooled but allows options.
func DecodeRequestPooledWithOptions(secret string, buf []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, nil, opts)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeReplyPooled decodes a reply packet and returns a packet from an
// internal pool. The returned packet must be released with (*Packet).Release.
func DecodeReplyPooled(secret string, buf []byte, requestAuth []byte) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, requestAuth, nil)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeReplyPooledWithOptions is like DecodeReplyPooled but allows options.
func DecodeReplyPooledWithOptions(secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = packetPool.Get().(*Packet)
	err = decodePacketTo(p, secret, buf, requestAuth, opts)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeRequestLazy decodes only the packet header and keeps attributes in
// raw form for lazy access via RawAVPs.
func DecodeRequestLazy(secret string, buf []byte) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, nil, nil)
}

// DecodeRequestLazyWithOptions is like DecodeRequestLazy but allows options.
func DecodeRequestLazyWithOptions(secret string, buf []byte, opts *DecodeOptions) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, nil, opts)
}

// DecodeReplyLazy decodes only the packet header and keeps attributes in raw
// form for lazy access via RawAVPs.
func DecodeReplyLazy(secret string, buf []byte, requestAuth []byte) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, requestAuth, nil)
}

// DecodeReplyLazyWithOptions is like DecodeReplyLazy but allows options.
func DecodeReplyLazyWithOptions(secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	return decodePacketLazy(secret, buf, requestAuth, opts)
}

// decode request/reply
func decodePacket(Secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	err = decodePacketTo(p, Secret, buf, requestAuth, opts)
	return p, err
}

func decodePacketTo(p *Packet, Secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) error {
	err := decodePacketHeaderTo(p, Secret, buf, requestAuth)
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
	err = p.checkMessageAuthenticator(requestAuth, opts)
	if err != nil {
		return err
	}
	return nil
}

func decodePacketLazy(Secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	p, err = decodePacketHeader(Secret, buf, requestAuth)
	if err != nil {
		return p, err
	}
	p.RawAVPs = buf[20:]

	// Verify the Message-Authenticator
	// Note: Message-Authenticator verification requires walking the attributes
	// if we want to be fully lazy, we could defer this, but it's safer to check now.
	err = p.checkMessageAuthenticator(requestAuth, opts)
	if err != nil {
		return p, err
	}
	return p, nil
}

func decodePacketHeader(Secret string, buf []byte, requestAuth []byte) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	err = decodePacketHeaderTo(p, Secret, buf, requestAuth)
	return p, err
}

func decodePacketHeaderTo(p *Packet, Secret string, buf []byte, requestAuth []byte) error {
	if len(buf) < 20 {
		return errors.New("invalid length")
	}

	p.Secret = Secret
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:20])

	if err := p.checkAuthenticator(buf, requestAuth); err != nil {
		return err
	}
	return nil
}

func (p *Packet) checkAuthenticator(buf []byte, requestAuth []byte) (err error) {
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
		hasher.Write(requestAuth)
	}
	hasher.Write(buf[20:])
	hasher.Write([]byte(p.Secret))
	expected := hasher.Sum(nil)
	if !bytes.Equal(expected, p.Authenticator[:]) {
		return ErrAuthenticatorCheckFail
	}
	// ok
	return nil
}

// check value of Message-Authenticator AVP
func (p *Packet) checkMessageAuthenticator(requestAuth []byte, opts *DecodeOptions) (err error) {
	avp := p.GetAVP(AttrMessageAuthenticator)
	if avp == nil {
		if opts != nil && opts.RequireMessageAuthenticator && p.Code.IsAccess() {
			return ErrMessageAuthenticatorMissing
		}
		return nil
	}
	origValue := make([]byte, 16)
	copy(origValue, avp.Value)
	// restore after validation
	defer func() { copy(avp.Value, origValue) }()

	if !p.Code.IsRequest() {
		// orig authenticator from request to verify reply
		pAuth := make([]byte, 16)
		copy(pAuth, p.Authenticator[:])
		defer func() { copy(p.Authenticator[:], pAuth) }()
		copy(p.Authenticator[:], requestAuth)
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

// GetUsername returns the value of User-Name as a string, if present.
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

// GetPassword returns the decrypted User-Password, if present.
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

// AddPassword adds (or replaces) the User-Password attribute, encrypting it as
// required by the RADIUS protocol using the packet Secret and Authenticator.
func (p *Packet) AddPassword(password string) {
	p.SetAVP(AVP{
		Type:  AttrUserPassword,
		Value: avpPassword.Encode(password, p.Secret, p.Authenticator[:]),
	})
}

// GetNasIpAddress returns NAS-IP-Address as a net.IP, if present.
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

// GetAcctStatusType returns Acct-Status-Type if present, or 0 otherwise.
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

// GetAcctSessionId returns Acct-Session-Id as a string, if present.
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

// GetAcctTotalOutputOctets returns the total output octets by combining
// Acct-Output-Octets and Acct-Output-Gigawords when present.
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

// GetAcctTotalInputOctets returns the total input octets by combining
// Acct-Input-Octets and Acct-Input-Gigawords when present.
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

// GetNASPort returns NAS-Port, if present.
//
// Note: some clients (for example strongSwan) use this to carry an IKE identity.
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

// GetNASIdentifier returns NAS-Identifier, if present.
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

// GetEAPMessage reassembles and decodes the EAP-Message from the packet.
// Per RFC 3579 §3.1, a single EAP packet may be split across multiple
// consecutive EAP-Message attributes (each carrying at most 253 bytes).
// All fragments are concatenated in order before decoding.
func (p *Packet) GetEAPMessage() *EapPacket {
	var buf []byte
	p.EachAVP(func(a AVP) bool {
		if a.Type == AttrEAPMessage {
			buf = append(buf, a.Value...)
		}
		return true
	})
	if len(buf) == 0 {
		return nil
	}
	eap, err := EapDecode(buf)
	if err != nil {
		return nil
	}
	return eap
}

// GetNASPortType returns NAS-Port-Type if present, or 0 otherwise.
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

// GetServiceType returns Service-Type if present, or 0 otherwise.
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
