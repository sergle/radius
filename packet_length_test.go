package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// lengthTestCase is an encoded packet plus the request authenticator a reply
// is verified against (nil for requests).
type lengthTestCase struct {
	name        string
	buf         []byte
	requestAuth []byte
}

func lengthTestCases(t *testing.T) []lengthTestCase {
	t.Helper()
	const secret = "testing123"
	encode := func(p *Packet) []byte {
		b, err := p.Encode()
		if err != nil {
			t.Fatalf("Encode %v failed: %v", p.Code, err)
		}
		return b
	}

	accessReq := Request(AccessRequest, secret)
	accessReq.Identifier = 1
	accessReq.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	accessReq.AddPassword("s3cret")
	accessReqBuf := encode(accessReq)

	acctReq := Request(AccountingRequest, secret)
	acctReq.Identifier = 2
	acctReq.AddAVP(AVP{Type: AttrAcctStatusType, Value: []byte{0, 0, 0, 1}})
	acctReq.AddAVP(AVP{Type: AttrAcctSessionId, Value: []byte("session-1")})
	acctReqBuf := encode(acctReq)

	disconnectReq := Request(DisconnectRequest, secret)
	disconnectReq.Identifier = 3
	disconnectReq.AddAVP(AVP{Type: AttrUserName, Value: []byte("bob")})
	disconnectReqBuf := encode(disconnectReq)

	accept := accessReq.ReplyAccept()
	accept.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("welcome")})
	acceptBuf := encode(accept)

	acctResp := acctReq.ReplyAccountingResponse()
	acctRespBuf := encode(acctResp)

	return []lengthTestCase{
		{"Access-Request", accessReqBuf, nil},
		{"Accounting-Request", acctReqBuf, nil},
		{"Disconnect-Request", disconnectReqBuf, nil},
		{"Access-Accept", acceptBuf, accessReq.Authenticator[:]},
		{"Accounting-Response", acctRespBuf, acctReq.Authenticator[:]},
	}
}

func decodeLengthTestCase(tc lengthTestCase, buf []byte, mode string, opts *DecodeOptions) (*Packet, error) {
	const secret = "testing123"
	if tc.requestAuth == nil {
		switch mode {
		case "normal":
			return DecodeRequestWithOptions(secret, buf, opts)
		case "pooled":
			return DecodeRequestPooledWithOptions(secret, buf, opts)
		case "lazy pooled":
			return DecodeRequestLazyPooledWithOptions(secret, buf, opts)
		default:
			return DecodeRequestLazyWithOptions(secret, buf, opts)
		}
	}
	switch mode {
	case "normal":
		return DecodeReplyWithOptions(secret, buf, tc.requestAuth, opts)
	case "pooled":
		return DecodeReplyPooledWithOptions(secret, buf, tc.requestAuth, opts)
	case "lazy pooled":
		return DecodeReplyLazyPooledWithOptions(secret, buf, tc.requestAuth, opts)
	default:
		return DecodeReplyLazyWithOptions(secret, buf, tc.requestAuth, opts)
	}
}

var lengthDecodeModes = []string{"normal", "pooled", "lazy", "lazy pooled"}

var requireMA = &DecodeOptions{RequireMessageAuthenticator: true}

// Octets past the Length field are padding and must be ignored (RFC 2865 section 3).
func TestDecodeIgnoresPaddingPastLength(t *testing.T) {
	for _, tc := range lengthTestCases(t) {
		want, err := decodeLengthTestCase(tc, tc.buf, "normal", requireMA)
		if err != nil {
			t.Fatalf("%s: decode without padding failed: %v", tc.name, err)
		}
		for _, mode := range lengthDecodeModes {
			for _, pad := range []int{1, 2, 17, 64} {
				padded := append(append([]byte(nil), tc.buf...), bytes.Repeat([]byte{0xAB}, pad)...)
				got, err := decodeLengthTestCase(tc, padded, mode, requireMA)
				if err != nil {
					t.Errorf("%s/%s/pad=%d: decode failed: %v", tc.name, mode, pad, err)
					continue
				}
				if strings.HasPrefix(mode, "lazy") {
					if !bytes.Equal(got.RawAVPs, tc.buf[packetHeaderLen:]) {
						t.Errorf("%s/%s/pad=%d: RawAVPs include padding: got %d bytes, want %d",
							tc.name, mode, pad, len(got.RawAVPs), len(tc.buf)-packetHeaderLen)
					}
				} else if (len(got.AVPs) > 0 || len(want.AVPs) > 0) && !reflect.DeepEqual(got.AVPs, want.AVPs) {
					t.Errorf("%s/%s/pad=%d: AVPs = %v, want %v", tc.name, mode, pad, got.AVPs, want.AVPs)
				}
				if strings.HasSuffix(mode, "pooled") {
					got.Release()
				}
			}
		}
	}
}

// A packet shorter than its Length field must be discarded (RFC 2865 section 3).
func TestDecodeRejectsPacketShorterThanLength(t *testing.T) {
	for _, tc := range lengthTestCases(t) {
		seen := map[int]bool{}
		for _, n := range []int{len(tc.buf) - 1, len(tc.buf) - messageAuthenticatorLen, packetHeaderLen, packetHeaderLen - 1} {
			if n < 0 || n >= len(tc.buf) || seen[n] {
				continue
			}
			seen[n] = true
			for _, mode := range lengthDecodeModes {
				short := append([]byte(nil), tc.buf[:n]...)
				if _, err := decodeLengthTestCase(tc, short, mode, nil); !errors.Is(err, ErrInvalidPacketLength) {
					t.Errorf("%s/len=%d of %d/%s: got %v, want %v", tc.name, n, len(tc.buf), mode, err, ErrInvalidPacketLength)
				}
			}
		}
	}
}

// The Length field must be within packetHeaderLen..maxPacketLen (RFC 2865 section 3).
func TestDecodeRejectsLengthOutOfRange(t *testing.T) {
	for _, tc := range lengthTestCases(t) {
		for _, length := range []int{0, 1, packetHeaderLen - 1, maxPacketLen + 1, 0xFFFF} {
			buf := append([]byte(nil), tc.buf...)
			if len(buf) < length {
				// make the buffer long enough so only the range check can fail
				buf = append(buf, make([]byte, length-len(buf))...)
			}
			binary.BigEndian.PutUint16(buf[2:4], uint16(length))
			for _, mode := range lengthDecodeModes {
				if _, err := decodeLengthTestCase(tc, buf, mode, nil); !errors.Is(err, ErrInvalidPacketLength) {
					t.Errorf("%s/length=%d/%s: got %v, want %v", tc.name, length, mode, err, ErrInvalidPacketLength)
				}
			}
		}
	}
}
