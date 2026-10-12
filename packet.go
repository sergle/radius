package radius

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net"
	"slices"
	"strconv"
)

var ErrMessageAuthenticatorCheckFail = fmt.Errorf("RADIUS Message-Authenticator verification failed")
var ErrAuthenticatorCheckFail = fmt.Errorf("RADIUS Authenticator verification failed")
var ErrMessageAuthenticatorMissing = fmt.Errorf("RADIUS Message-Authenticator missing")
var ErrInvalidPacketLength = fmt.Errorf("RADIUS packet Length field is invalid")
var ErrNoRequestAuthenticator = fmt.Errorf("RADIUS reply has no request authenticator, create it with request.Reply()")
var ErrTunnelPasswordInRequest = fmt.Errorf("RADIUS Access-Request and Status-Server can't carry Tunnel-Password (encrypt=2) values")

// the size of the RADIUS packet header (RFC 2865 section 3)
// Code (1), Identifier (1), Length (2) and Authenticator (16)
const authenticatorLen = 16
const packetHeaderLen = 1 + 1 + 2 + authenticatorLen

// maximum RADIUS packet length (RFC 2865 section 3)
const maxPacketLen = 4096

// length of a Message-Authenticator attribute:
// 2-byte header plus a 16-byte HMAC-MD5 value (RFC 3579 section 3.2).
const messageAuthenticatorLen = 2 + md5.Size

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
//
// Create packets with Request, RadClient.NewRequest, request.Reply (ReplyAccept etc.)
// or the Decode functions: they set the authenticators that hide encrypted values.
// A reply built by hand has no request authenticator, so encrypting fails with
// ErrNoRequestAuthenticator.
type Packet struct {
	Secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [authenticatorLen]byte
	AVPs          []AVP
	RawAVPs       []byte // Unparsed attributes for lazy decoding
	ClientAddr    string

	requestAuth [authenticatorLen]byte // set on decoded replies
}

// zeroAuthenticator hides values in requests whose Request Authenticator is computed (RFC 2866, 5176).
var zeroAuthenticator [authenticatorLen]byte

// cryptAuthenticator returns the Request Authenticator that hides values of encrypt= method:
// all zeros for Accounting, CoA and Disconnect requests, as FreeRADIUS encodes them
// (FreeRADIUS decodes their encrypt=1 values with the packet's own; we stay symmetric),
// and for encrypt=2 in any request, as FreeRADIUS decodes them (we don't encode those).
// Access-Request and Status-Server hide encrypt=1 with their own, replies with the request's.
func (p *Packet) cryptAuthenticator(method int) []byte {
	if p.Code.IsRequest() && (!p.Code.hasRandomAuthenticator() || method == encryptTunnelPassword) {
		return zeroAuthenticator[:]
	}
	if p.requestAuth != zeroAuthenticator {
		return p.requestAuth[:]
	}
	return p.Authenticator[:]
}

// ensureAuthenticator generates a random Request Authenticator if the code needs one and it isn't set;
// kept in p, so values hidden with it and reply checks match what Encode sends.
func (p *Packet) ensureAuthenticator() error {
	if p.Code.hasRandomAuthenticator() && p.Authenticator == zeroAuthenticator {
		if _, err := rand.Read(p.Authenticator[:]); err != nil {
			return err
		}
	}
	return nil
}

// encryptAuthenticator is cryptAuthenticator for hiding a value; a reply needs the request's,
// and encrypt=2 isn't allowed in Access-Request or Status-Server (RFC 2868 section 3.5; FreeRADIUS refuses it).
func (p *Packet) encryptAuthenticator(method int) ([]byte, error) {
	if method == encryptTunnelPassword && p.Code.hasRandomAuthenticator() {
		return nil, ErrTunnelPasswordInRequest
	}
	if err := p.ensureAuthenticator(); err != nil {
		return nil, err
	}
	auth := p.cryptAuthenticator(method)
	if !p.Code.IsRequest() && [authenticatorLen]byte(auth) == zeroAuthenticator {
		return nil, ErrNoRequestAuthenticator
	}
	return auth, nil
}

var packetPool = newPool(func() *Packet {
	return &Packet{
		AVPs: make([]AVP, 0, 10),
	}
})

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
	p.Authenticator = [authenticatorLen]byte{}
	p.requestAuth = [authenticatorLen]byte{}
	p.AVPs = p.AVPs[:0]
	p.RawAVPs = nil
	p.ClientAddr = ""
}

// Copy returns a deep copy of the packet, including AVPs, RawAVPs and ClientAddr.
// The copy shares no memory with p, so it stays valid after p is released
// or its decode buffer is reused.
func (p *Packet) Copy() *Packet {
	outP := &Packet{
		Secret:        p.Secret,
		Code:          p.Code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
		ClientAddr:    p.ClientAddr,
		requestAuth:   p.requestAuth,
	}
	if p.AVPs != nil {
		outP.AVPs = make([]AVP, len(p.AVPs))
		for i := range p.AVPs {
			outP.AVPs[i] = p.AVPs[i].Copy()
		}
	}
	if p.RawAVPs != nil {
		outP.RawAVPs = append([]byte{}, p.RawAVPs...)
	}
	return outP
}

// Encode serializes the packet into a new byte slice.
//
// If the packet Code requires it, Encode will compute and include
// Message-Authenticator and the packet Authenticator in the output.
// A Message-Authenticator not already in the packet is added as the first attribute.
// Replies are left unchanged; a request's Authenticator is set to the one
// sent (random for an Access-Request or Status-Server if unset).
func (p *Packet) Encode() (b []byte, err error) {
	b = make([]byte, maxPacketLen)
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
	if err := p.ensureAuthenticator(); err != nil {
		return 0, err
	}

	// a new Message-Authenticator goes first (Blast-RADIUS, CVE-2024-3596)
	addMA := p.Code.hasMessageAuthenticator() && !p.HasAVP(AttrMessageAuthenticator)
	n, err = p.encodeNoHashTo(b, addMA)
	if err != nil {
		return
	}

	// For non-Access requests (for example Accounting/CoA/Disconnect), the
	// Request Authenticator is computed using a 16-byte zero vector in the
	// hash input per RFC 2866/5176. Ensure we don't accidentally hash any
	// caller-provided authenticator value.
	if p.Code.IsRequest() && !p.Code.hasRandomAuthenticator() {
		clear(b[4:packetHeaderLen])
	}

	if addMA || p.HasAVP(AttrMessageAuthenticator) {
		// an existing Message-Authenticator is filled in place
		off := packetHeaderLen
		if !addMA {
			off = findAttributeOffset(b[:n], AttrMessageAuthenticator)
			if off < 0 || b[off+1] != messageAuthenticatorLen {
				return 0, errors.New("invalid Message-Authenticator")
			}
		}
		value := b[off+2 : off+messageAuthenticatorLen]
		clear(value)
		hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
		hasher.Write(b[:n])
		copy(value, hasher.Sum(nil))
	}

	// fix up the authenticator
	// handle request and response stuff.
	// here only handle response part.
	switch p.Code {
	case AccessRequest, StatusServer:
	case DisconnectRequest, DisconnectAccept, DisconnectReject:
		fallthrough
	case CoARequest, CoAAccept, CoAReject:
		fallthrough
	case AccessAccept, AccessReject, AccessChallenge, AccountingRequest, AccountingResponse:
		hasher := crypto.Hash(crypto.MD5).New()
		hasher.Write(b[:n])
		hasher.Write([]byte(p.Secret))
		copy(b[4:packetHeaderLen], hasher.Sum(nil))
		// a request's Authenticator is an output: keep it for reply checks
		if p.Code.IsRequest() {
			copy(p.Authenticator[:], b[4:packetHeaderLen])
		}
	default:
		return 0, fmt.Errorf("not handle p.Code %d", p.Code)
	}

	return n, nil
}

func (p *Packet) encodeNoHash() (b []byte, err error) {
	b = make([]byte, maxPacketLen)
	n, err := p.encodeNoHashTo(b, false)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

// encodeNoHashTo writes the packet without hashing; withMA reserves a zeroed
// Message-Authenticator as the first attribute.
func (p *Packet) encodeNoHashTo(b []byte, withMA bool) (n int, err error) {
	if len(b) < packetHeaderLen {
		return 0, errors.New("buffer too small")
	}
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:packetHeaderLen], p.Authenticator[:])
	written := packetHeaderLen

	if withMA {
		if len(b) < written+messageAuthenticatorLen {
			return 0, errors.New("buffer too small")
		}
		b[written] = uint8(AttrMessageAuthenticator)
		b[written+1] = messageAuthenticatorLen
		clear(b[written+2 : written+messageAuthenticatorLen])
		written += messageAuthenticatorLen
	}

	if len(p.AVPs) > 0 {
		bb := b[written:]
		for i := range p.AVPs {
			n, err := p.AVPs[i].Encode(bb)
			written += n
			if err != nil {
				return 0, err
			}
			bb = bb[n:]
		}
	} else if len(p.RawAVPs) > 0 {
		if len(b) < written+len(p.RawAVPs) {
			return 0, errors.New("buffer too small")
		}
		copy(b[written:], p.RawAVPs)
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
	for _, a := range rawAttrs(p.RawAVPs) {
		if a.Type == attrType {
			return true
		}
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
	for _, a := range rawAttrs(p.RawAVPs) {
		if a.Type == attrType {
			return &AVP{Type: a.Type, Value: a.Value}
		}
	}
	return nil
}

// EachAVP iterates over attributes in the packet, calling fn for each.
//
// If fn returns false, iteration stops early. A nil packet has no attributes.
func (p *Packet) EachAVP(fn func(a AVP) bool) {
	if p == nil {
		return
	}
	if len(p.AVPs) > 0 {
		for i := range p.AVPs {
			if !fn(p.AVPs[i]) {
				return
			}
		}
		return
	}

	for _, a := range rawAttrs(p.RawAVPs) {
		if !fn(a) {
			return
		}
	}
}

// rawAttrs iterates over encoded attributes in b, yielding each one's offset in b.
// It stops at the end of b or at the first malformed attribute.
func rawAttrs(b []byte) iter.Seq2[int, AVP] {
	return func(yield func(int, AVP) bool) {
		for off := 0; len(b)-off >= 2; {
			length := int(b[off+1])
			if length > len(b)-off || length < 2 {
				return
			}
			if !yield(off, AVP{Type: AttributeType(b[off]), Value: b[off+2 : off+length]}) {
				return
			}
			off += length
		}
	}
}

// SetAVP removes all attributes of the same type and then adds avp.
func (p *Packet) SetAVP(avp AVP) {
	p.DeleteOneType(avp.Type)
	p.AddAVP(avp)
}

// AddAVP appends avp to the packet's attribute list.
func (p *Packet) AddAVP(avps ...AVP) {
	p.AVPs = append(p.AVPs, avps...)
}

// AddVSA adds a Vendor-Specific Attribute (VSA) to the packet, split over several if needed (WiMAX).
func (p *Packet) AddVSA(vsa VSA) {
	p.AddAVP(vsa.ToAVPList()...)
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
// For Access-Request and Status-Server packets, a new request Authenticator is also generated and
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

	if code.hasRandomAuthenticator() {
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

func (p *Packet) replyWithCode(code PacketCode) *Packet {
	pac := p.Reply()
	pac.Code = code
	return pac
}

// ReplyAccept creates an Access-Accept reply to this packet.
func (p *Packet) ReplyAccept() *Packet { return p.replyWithCode(AccessAccept) }

// ReplyReject creates an Access-Reject reply to this packet.
func (p *Packet) ReplyReject() *Packet { return p.replyWithCode(AccessReject) }

// ReplyChallenge creates an Access-Challenge reply to this packet.
func (p *Packet) ReplyChallenge() *Packet { return p.replyWithCode(AccessChallenge) }

// ReplyAccountingResponse creates an Accounting-Response reply to this packet.
func (p *Packet) ReplyAccountingResponse() *Packet { return p.replyWithCode(AccountingResponse) }

// ReplyDisconnectAccept creates a Disconnect-Accept reply to this packet.
func (p *Packet) ReplyDisconnectAccept() *Packet { return p.replyWithCode(DisconnectAccept) }

// ReplyDisconnectReject creates a Disconnect-Reject reply to this packet.
func (p *Packet) ReplyDisconnectReject() *Packet { return p.replyWithCode(DisconnectReject) }

// ReplyCoAAccept creates a CoA-Accept reply to this packet.
func (p *Packet) ReplyCoAAccept() *Packet { return p.replyWithCode(CoAAccept) }

// ReplyCoAReject creates a CoA-Reject reply to this packet.
func (p *Packet) ReplyCoAReject() *Packet { return p.replyWithCode(CoAReject) }

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
	p = packetPool.Get()
	err = decodePacketTo(p, secret, buf, nil, nil)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeRequestPooledWithOptions is like DecodeRequestPooled but allows options.
func DecodeRequestPooledWithOptions(secret string, buf []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = packetPool.Get()
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
	p = packetPool.Get()
	err = decodePacketTo(p, secret, buf, requestAuth, nil)
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// DecodeReplyPooledWithOptions is like DecodeReplyPooled but allows options.
func DecodeReplyPooledWithOptions(secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = packetPool.Get()
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
	buf, err := decodePacketHeaderTo(p, Secret, buf, requestAuth)
	if err != nil {
		return err
	}

	//read attributes, remembering where the first Message-Authenticator is
	maOffset := -1
	b := buf[packetHeaderLen:]
	for pos := packetHeaderLen; len(b) >= 2; {
		length := uint8(b[1])
		if int(length) > len(b) || length < 2 {
			return errors.New("invalid length")
		}
		attr := AVP{}
		attr.Type = AttributeType(b[0])
		attr.Value = b[2:length]
		p.AVPs = append(p.AVPs, attr)
		if attr.Type == AttrMessageAuthenticator && maOffset < 0 {
			maOffset = pos
		}
		pos += int(length)
		b = b[length:]
	}

	// Verify the Message-Authenticator
	err = p.checkMessageAuthenticator(buf, maOffset, requestAuth, opts)
	if err != nil {
		return err
	}
	return nil
}

func decodePacketLazy(Secret string, buf []byte, requestAuth []byte, opts *DecodeOptions) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	buf, err = decodePacketHeaderTo(p, Secret, buf, requestAuth)
	if err != nil {
		return p, err
	}
	p.RawAVPs = buf[packetHeaderLen:]

	// Verify the Message-Authenticator
	// Note: Message-Authenticator verification requires walking the attributes
	// if we want to be fully lazy, we could defer this, but it's safer to check now.
	err = p.checkMessageAuthenticator(buf, findAttributeOffset(buf, AttrMessageAuthenticator), requestAuth, opts)
	if err != nil {
		return p, err
	}
	return p, nil
}

// decodePacketHeaderTo verifies the header and returns buf cut to its Length field.
func decodePacketHeaderTo(p *Packet, Secret string, buf []byte, requestAuth []byte) ([]byte, error) {
	if len(buf) < packetHeaderLen {
		return nil, ErrInvalidPacketLength
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length < packetHeaderLen || length > maxPacketLen || length > len(buf) {
		return nil, ErrInvalidPacketLength
	}
	buf = buf[:length]

	p.Secret = Secret
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:packetHeaderLen])
	if !p.Code.IsRequest() {
		copy(p.requestAuth[:], requestAuth)
	}

	if err := p.checkAuthenticator(buf, requestAuth); err != nil {
		return nil, err
	}
	return buf, nil
}

func (p *Packet) checkAuthenticator(buf []byte, requestAuth []byte) (err error) {
	if p.Code.hasRandomAuthenticator() {
		// it has random authenticator, do not verify
		return nil
	}

	hasher := crypto.Hash(crypto.MD5).New()
	hasher.Write(buf[0:4])
	if p.Code.IsRequest() {
		// Accounting, PoD, CoA
		hasher.Write(make([]byte, authenticatorLen))
	} else {
		// value from request packet
		hasher.Write(requestAuth)
	}
	hasher.Write(buf[packetHeaderLen:])
	hasher.Write([]byte(p.Secret))
	expected := hasher.Sum(nil)
	if !hmac.Equal(expected, p.Authenticator[:]) {
		return ErrAuthenticatorCheckFail
	}
	// ok
	return nil
}

// findAttributeOffset returns the offset in buf of the first attribute of the
// given type, or -1 if there is none before the end or a malformed attribute.
func findAttributeOffset(buf []byte, attrType AttributeType) int {
	for off, a := range rawAttrs(buf[packetHeaderLen:]) {
		if a.Type == attrType {
			return packetHeaderLen + off
		}
	}
	return -1
}

// check value of Message-Authenticator AVP against the received bytes in buf;
// offset is the position of the attribute in buf, or -1 if it is absent
func (p *Packet) checkMessageAuthenticator(buf []byte, offset int, requestAuth []byte, opts *DecodeOptions) (err error) {
	if offset < 0 {
		// Status-Server requires it (RFC 5997 section 3)
		if p.Code == StatusServer || opts != nil && opts.RequireMessageAuthenticator && p.Code.IsAccess() {
			return ErrMessageAuthenticatorMissing
		}
		return nil
	}
	if buf[offset+1] != messageAuthenticatorLen {
		return ErrMessageAuthenticatorCheckFail
	}
	value := buf[offset+2 : offset+messageAuthenticatorLen]

	// HMAC-MD5 over the packet with the Message-Authenticator value zeroed;
	// replies are hashed with the Request Authenticator in place of their own,
	// Accounting, CoA and Disconnect requests with zeros (RFC 5176 section 3.5).
	var zero [md5.Size]byte
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(buf[0:4])
	switch {
	case p.Code.hasRandomAuthenticator():
		hasher.Write(buf[4:packetHeaderLen])
	case p.Code.IsRequest():
		hasher.Write(zeroAuthenticator[:])
	default:
		hasher.Write(requestAuth)
	}
	hasher.Write(buf[packetHeaderLen : offset+2])
	hasher.Write(zero[:])
	hasher.Write(buf[offset+messageAuthenticatorLen:])
	if !hmac.Equal(hasher.Sum(nil), value) {
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

// decodeAVP decodes the first attribute of type t, or returns nil if absent.
func (p *Packet) decodeAVP(t AttributeType) any {
	avp := p.GetAVP(t)
	if avp == nil {
		return nil
	}
	return avp.Decode(p)
}

// getString returns attribute t as a string, accepting raw []byte.
func (p *Packet) getString(t AttributeType) string {
	switch v := p.decodeAVP(t).(type) {
	case string:
		return v
	case []byte:
		return string(v)
	}
	return ""
}

// getUint32 returns attribute t as E, accepting uint32 or 4-byte raw values.
func getUint32[E ~uint32](p *Packet, t AttributeType) E {
	switch v := p.decodeAVP(t).(type) {
	case E:
		return v
	case uint32:
		return E(v)
	case []byte:
		if len(v) == uint32Size {
			return E(binary.BigEndian.Uint32(v))
		}
	}
	return 0
}

// GetUsername returns the value of User-Name as a string, if present.
func (p *Packet) GetUsername() (username string) {
	return p.getString(AttrUserName)
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

// AddTunnelPassword adds a Tunnel-Password attribute (RFC 2868) encrypted
// with the packet Secret and Request Authenticator.
// A reply must be created with request.Reply(), else ErrNoRequestAuthenticator;
// Access-Request and Status-Server can't carry it (ErrTunnelPasswordInRequest).
func (p *Packet) AddTunnelPassword(tag uint8, password string) error {
	auth, err := p.encryptAuthenticator(encryptTunnelPassword)
	if err != nil {
		return err
	}
	v, err := avpTunnelPassword.Encode(tag, password, p.Secret, auth)
	if err != nil {
		return err
	}
	p.AddAVP(AVP{Type: AttrTunnelPassword, Value: v})
	return nil
}

// GetTunnelPassword returns the tag and decrypted value of the first Tunnel-Password.
func (p *Packet) GetTunnelPassword() (tag uint8, password string, ok bool) {
	avp := p.GetAVP(AttrTunnelPassword)
	if avp == nil {
		return 0, "", false
	}
	return avpTunnelPassword.decrypt(p, avp.Value)
}

// AddPassword adds (or replaces) the User-Password attribute, encrypting it as
// required by the RADIUS protocol using the packet Secret and Authenticator.
func (p *Packet) AddPassword(password string) {
	// no error return: on failure the password is hidden with the current authenticator, as before
	_ = p.ensureAuthenticator()
	p.SetAVP(AVP{
		Type:  AttrUserPassword,
		Value: avpPassword.Encode(password, p.Secret, p.cryptAuthenticator(encryptUserPassword)),
	})
}

// GetNasIpAddress returns NAS-IP-Address as a net.IP, if present.
func (p *Packet) GetNasIpAddress() (ip net.IP) {
	switch v := p.decodeAVP(AttrNASIPAddress).(type) {
	case net.IP:
		return v
	case []byte:
		return net.IP(v)
	}
	return nil
}

// GetAcctStatusType returns Acct-Status-Type if present, or 0 otherwise.
func (p *Packet) GetAcctStatusType() AcctStatusTypeEnum {
	return getUint32[AcctStatusTypeEnum](p, AttrAcctStatusType)
}

// GetAcctSessionId returns Acct-Session-Id as a string, if present.
func (p *Packet) GetAcctSessionId() string {
	return p.getString(AttrAcctSessionId)
}

// GetAcctTotalOutputOctets returns the total output octets by combining
// Acct-Output-Octets and Acct-Output-Gigawords when present.
func (p *Packet) GetAcctTotalOutputOctets() uint64 {
	return uint64(getUint32[uint32](p, AttrAcctOutputOctets)) +
		uint64(getUint32[uint32](p, AttrAcctOutputGigawords))<<32
}

// GetAcctTotalInputOctets returns the total input octets by combining
// Acct-Input-Octets and Acct-Input-Gigawords when present.
func (p *Packet) GetAcctTotalInputOctets() uint64 {
	return uint64(getUint32[uint32](p, AttrAcctInputOctets)) +
		uint64(getUint32[uint32](p, AttrAcctInputGigawords))<<32
}

// GetNASPort returns NAS-Port, if present.
//
// Note: some clients (for example strongSwan) use this to carry an IKE identity.
func (p *Packet) GetNASPort() uint32 {
	return getUint32[uint32](p, AttrNASPort)
}

// GetNASIdentifier returns NAS-Identifier, if present.
func (p *Packet) GetNASIdentifier() string {
	return p.getString(AttrNASIdentifier)
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

// SetEAPMessage replaces any EAP-Message attributes with eap, split into
// consecutive 253-byte fragments as needed (RFC 3579 §3.1).
func (p *Packet) SetEAPMessage(eap *EapPacket) {
	p.AVPs = slices.DeleteFunc(p.AVPs, func(a AVP) bool { return a.Type == AttrEAPMessage })
	p.AddAVP(eap.ToEAPMessages()...)
}

// GetNASPortType returns NAS-Port-Type if present, or 0 otherwise.
func (p *Packet) GetNASPortType() NASPortTypeEnum {
	return getUint32[NASPortTypeEnum](p, AttrNASPortType)
}

// GetServiceType returns Service-Type if present, or 0 otherwise.
func (p *Packet) GetServiceType() ServiceTypeEnum {
	return getUint32[ServiceTypeEnum](p, AttrServiceType)
}

// SetVLAN adds the three-attribute combination required for dynamic VLAN assignment
// per RFC 3580 §3.31: Tunnel-Type=VLAN, Tunnel-Medium-Type=802, and
// Tunnel-Private-Group-ID set to the decimal VLAN ID string.
func (p *Packet) SetVLAN(vlanID uint16) {
	tunnelType := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelType, uint32(TunnelTypeEnumVLAN))
	p.SetAVP(AVP{Type: AttrTunnelType, Value: tunnelType})

	tunnelMedium := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelMedium, uint32(TunnelMediumTypeEnum802))
	p.SetAVP(AVP{Type: AttrTunnelMediumType, Value: tunnelMedium})

	p.SetAVP(AVP{Type: AttrTunnelPrivateGroupID, Value: []byte(strconv.Itoa(int(vlanID)))})
}

// GetVLAN returns the VLAN ID from the packet if the RFC 3580 §3.31 tunnel
// attribute combination is present and valid (Tunnel-Type=VLAN,
// Tunnel-Medium-Type=802, Tunnel-Private-Group-ID parseable as 1–4094).
// Returns 0, false if the combination is absent or invalid.
func (p *Packet) GetVLAN() (uint16, bool) {
	ttAVP := p.GetAVP(AttrTunnelType)
	tmAVP := p.GetAVP(AttrTunnelMediumType)
	pgAVP := p.GetAVP(AttrTunnelPrivateGroupID)
	if ttAVP == nil || tmAVP == nil || pgAVP == nil {
		return 0, false
	}

	ttVal := ttAVP.Decode(p)
	switch v := ttVal.(type) {
	case TunnelTypeEnum:
		if v != TunnelTypeEnumVLAN {
			return 0, false
		}
	case uint32:
		if TunnelTypeEnum(v) != TunnelTypeEnumVLAN {
			return 0, false
		}
	default:
		return 0, false
	}

	tmVal := tmAVP.Decode(p)
	switch v := tmVal.(type) {
	case TunnelMediumTypeEnum:
		if v != TunnelMediumTypeEnum802 {
			return 0, false
		}
	case uint32:
		if TunnelMediumTypeEnum(v) != TunnelMediumTypeEnum802 {
			return 0, false
		}
	default:
		return 0, false
	}

	pgVal := pgAVP.Decode(p)
	var pgStr string
	switch v := pgVal.(type) {
	case string:
		pgStr = v
	case []byte:
		pgStr = string(v)
	default:
		return 0, false
	}

	id, err := strconv.ParseUint(pgStr, 10, 16)
	if err != nil || id < 1 || id > 4094 {
		return 0, false
	}
	return uint16(id), true
}
