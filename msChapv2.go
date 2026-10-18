package radius

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ── MSCHAPv2 crypto (RFC 2759) ────────────────────────────────────────────────

// md4 computes the MD4 hash (RFC 1320).
func md4(msg []byte) []byte {
	m := append([]byte(nil), msg...)
	origLen := len(m)
	m = append(m, 0x80)
	for len(m)%64 != 56 {
		m = append(m, 0)
	}
	l := uint64(origLen) * 8
	for i := 0; i < 8; i++ {
		m = append(m, byte(l>>(uint(i)*8)))
	}

	h := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	for i := 0; i < len(m); i += 64 {
		var X [16]uint32
		for k := 0; k < 16; k++ {
			X[k] = binary.LittleEndian.Uint32(m[i+k*4:])
		}
		a, b, c, d := h[0], h[1], h[2], h[3]

		// Round 1: F(b,c,d) = (b&c)|((^b)&d), no constant
		for _, k := range [4]int{0, 4, 8, 12} {
			a = bits.RotateLeft32(a+((b&c)|((^b)&d))+X[k+0], 3)
			d = bits.RotateLeft32(d+((a&b)|((^a)&c))+X[k+1], 7)
			c = bits.RotateLeft32(c+((d&a)|((^d)&b))+X[k+2], 11)
			b = bits.RotateLeft32(b+((c&d)|((^c)&a))+X[k+3], 19)
		}
		// Round 2: G(b,c,d) = (b&c)|(b&d)|(c&d), constant 0x5A827999
		for _, k := range [4]int{0, 1, 2, 3} {
			a = bits.RotateLeft32(a+((b&c)|(b&d)|(c&d))+X[k+0]+0x5a827999, 3)
			d = bits.RotateLeft32(d+((a&b)|(a&c)|(b&c))+X[k+4]+0x5a827999, 5)
			c = bits.RotateLeft32(c+((d&a)|(d&b)|(a&b))+X[k+8]+0x5a827999, 9)
			b = bits.RotateLeft32(b+((c&d)|(c&a)|(d&a))+X[k+12]+0x5a827999, 13)
		}
		// Round 3: H(b,c,d) = b^c^d, constant 0x6ED9EBA1
		for _, ks := range [4][4]int{{0, 8, 4, 12}, {2, 10, 6, 14}, {1, 9, 5, 13}, {3, 11, 7, 15}} {
			a = bits.RotateLeft32(a+(b^c^d)+X[ks[0]]+0x6ed9eba1, 3)
			d = bits.RotateLeft32(d+(a^b^c)+X[ks[1]]+0x6ed9eba1, 9)
			c = bits.RotateLeft32(c+(d^a^b)+X[ks[2]]+0x6ed9eba1, 11)
			b = bits.RotateLeft32(b+(c^d^a)+X[ks[3]]+0x6ed9eba1, 15)
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}
	out := make([]byte, 16)
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}

// msChapDESKey expands a 7-byte key to an 8-byte DES key (RFC 2759 str_to_key).
func msChapDESKey(k7 []byte) []byte {
	k8 := make([]byte, 8)
	k8[0] = k7[0] >> 1
	k8[1] = ((k7[0] & 0x01) << 6) | (k7[1] >> 2)
	k8[2] = ((k7[1] & 0x03) << 5) | (k7[2] >> 3)
	k8[3] = ((k7[2] & 0x07) << 4) | (k7[3] >> 4)
	k8[4] = ((k7[3] & 0x0f) << 3) | (k7[4] >> 5)
	k8[5] = ((k7[4] & 0x1f) << 2) | (k7[5] >> 6)
	k8[6] = ((k7[5] & 0x3f) << 1) | (k7[6] >> 7)
	k8[7] = k7[6] & 0x7f
	for i := range k8 {
		k8[i] <<= 1
	}
	return k8
}

// MSCHAPv2NTHash computes NT-Hash = MD4(UTF-16LE(password)) (RFC 2759 §8.2).
func MSCHAPv2NTHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return md4(b)
}

// MSCHAPv2ChallengeHash computes SHA1(peerChallenge||authChallenge||username)[0:8]
// (RFC 2759 §8.3). authChallenge is the server-generated challenge.
func MSCHAPv2ChallengeHash(peerChallenge, authChallenge []byte, username string) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(username))
	return h.Sum(nil)[:8]
}

// MSCHAPv2NTResponse computes the 24-byte NT-Response (RFC 2759 §8.1).
// authChallenge is the server-generated challenge; peerChallenge is client-generated.
func MSCHAPv2NTResponse(authChallenge, peerChallenge []byte, username, password string) ([]byte, error) {
	challenge := MSCHAPv2ChallengeHash(peerChallenge, authChallenge, username)
	hash := MSCHAPv2NTHash(password)
	padded := make([]byte, 21) // NT-Hash (16 bytes) zero-padded to 21
	copy(padded, hash)
	out := make([]byte, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(msChapDESKey(padded[i*7 : i*7+7]))
		if err != nil {
			return nil, err
		}
		block.Encrypt(out[i*8:], challenge)
	}
	return out, nil
}

const mppeKeyLen = 16 // 128-bit MPPE key

// Magic constants of RFC 2759 §8.7 and RFC 3079 §3.4.
var (
	msChapV2AuthMagic1 = []byte("Magic server to client signing constant")
	msChapV2AuthMagic2 = []byte("Pad to make it do more than one iteration")
	mppeMasterMagic    = []byte("This is the MPPE Master Key")
	mppeRecvMagic      = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	mppeSendMagic      = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
)

// MSCHAPv2AuthenticatorResponse computes the "S=..." string sent in the
// MS-CHAP2-Success message (RFC 2759 §8.7).
func MSCHAPv2AuthenticatorResponse(authChallenge, peerChallenge, ntResponse []byte, username, password string) string {
	h := sha1.New()
	h.Write(md4(MSCHAPv2NTHash(password)))
	h.Write(ntResponse)
	h.Write(msChapV2AuthMagic1)
	digest := h.Sum(nil)

	h.Reset()
	h.Write(digest)
	h.Write(MSCHAPv2ChallengeHash(peerChallenge, authChallenge, username))
	h.Write(msChapV2AuthMagic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// msChapV2MasterKey implements GetMasterKey (RFC 3079 §3.4).
func msChapV2MasterKey(ntHash, ntResponse []byte) []byte {
	h := sha1.New()
	h.Write(md4(ntHash))
	h.Write(ntResponse)
	h.Write(mppeMasterMagic)
	return h.Sum(nil)[:mppeKeyLen]
}

// msChapV2StartKey implements GetAsymmetricStartKey (RFC 3079 §3.4).
func msChapV2StartKey(masterKey, magic []byte) []byte {
	var pad1, pad2 [40]byte
	for i := range pad2 {
		pad2[i] = 0xf2
	}
	h := sha1.New()
	h.Write(masterKey)
	h.Write(pad1[:])
	h.Write(magic)
	h.Write(pad2[:])
	return h.Sum(nil)[:mppeKeyLen]
}

// MSCHAPv2MPPEKeys derives the 128-bit MPPE keys for MS-MPPE-Send-Key and
// MS-MPPE-Recv-Key (RFC 3079 §3.4, server side).
func MSCHAPv2MPPEKeys(ntResponse []byte, password string) (sendKey, recvKey []byte) {
	master := msChapV2MasterKey(MSCHAPv2NTHash(password), ntResponse)
	return msChapV2StartKey(master, mppeSendMagic), msChapV2StartKey(master, mppeRecvMagic)
}

// Microsoft VSAs (RFC 2548) that StringMasked hides: MS-CHAP responses allow offline password guessing.
const (
	vendorMicrosoft VendorID   = 311
	msCHAPResponse  VendorAttr = 1
	msCHAP2Response VendorAttr = 25
)

type MsChapV2Packet struct {
	Eap    *EapPacket //The eap information when decrypting, does not use the data inside
	OpCode MsChapV2OpCode
	Data   []byte
}

func (p *MsChapV2Packet) ToEap() *EapPacket {
	eap := p.Eap.Copy()
	eap.Data = make([]byte, len(p.Data)+4)
	eap.Data[0] = byte(p.OpCode)
	eap.Data[1] = byte(eap.Identifier)
	binary.BigEndian.PutUint16(eap.Data[2:4], uint16(len(p.Data)+4))
	copy(eap.Data[4:], p.Data)
	return eap
}

func MsChapV2PacketFromEap(eap *EapPacket) (p *MsChapV2Packet, err error) {
	p = &MsChapV2Packet{
		Eap: eap,
	}
	if len(eap.Data) < 4 {
		return nil, fmt.Errorf("[MsChapV2PacketFromEap] protocol error 1, packet too small")
	}
	p.OpCode = MsChapV2OpCode(eap.Data[0])
	p.Data = append([]byte(nil), eap.Data[4:]...)
	return p, nil
}

// Does not include eap information
func (p *MsChapV2Packet) String() string {
	return fmt.Sprintf("OpCode:%s Data:[%#v]", p.OpCode, p.Data)
}

type MsChapV2OpCode uint8

const (
	MsChapV2OpCodeChallenge      MsChapV2OpCode = 1
	MsChapV2OpCodeResponse       MsChapV2OpCode = 2
	MsChapV2OpCodeSuccess        MsChapV2OpCode = 3
	MsChapV2OpCodeFailure        MsChapV2OpCode = 4
	MsChapV2OpCodeChangePassword MsChapV2OpCode = 7
)

func (c MsChapV2OpCode) String() string {
	switch c {
	case MsChapV2OpCodeChallenge:
		return "Challenge"
	case MsChapV2OpCodeResponse:
		return "Response"
	case MsChapV2OpCodeSuccess:
		return "Success"
	case MsChapV2OpCodeFailure:
		return "Failure"
	case MsChapV2OpCodeChangePassword:
		return "ChangePassword"
	default:
		return "unknow MsChapV2OpCode " + strconv.Itoa(int(c))
	}
}
