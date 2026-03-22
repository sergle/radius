package radius

import (
	"crypto"
	_ "crypto/md5"
	"fmt"
)

// ── AVP helpers ──────────────────────────────────────────────────────────────

func digestStr(p *Packet, t AttributeType, def ...string) string {
	avp := p.GetAVP(t)
	if avp == nil {
		if len(def) > 0 {
			return def[0]
		}
		return ""
	}
	return string(avp.Value)
}

func setDigestStr(p *Packet, t AttributeType, v string) {
	p.SetAVP(AVP{Type: t, Value: []byte(v)})
}

func addDigestStr(p *Packet, t AttributeType, v string) {
	p.AddAVP(AVP{Type: t, Value: []byte(v)})
}

func allDigestStr(p *Packet, t AttributeType) []string {
	var out []string
	p.EachAVP(func(a AVP) bool {
		if a.Type == t {
			out = append(out, string(a.Value))
		}
		return true
	})
	return out
}

// ── Crypto helpers ───────────────────────────────────────────────────────────

func md5Hex(parts ...string) string {
	h := crypto.MD5.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte(":"))
		}
		h.Write([]byte(p))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func digestComputeHA1(username, realm, password string) string {
	return md5Hex(username, realm, password)
}

// digestComputeHA2Auth computes H(A2) for qop=auth or when qop is absent:
//
//	MD5(method:uri)
func digestComputeHA2Auth(method, uri string) string {
	return md5Hex(method, uri)
}

// digestComputeHA2AuthInt computes H(A2) for qop=auth-int:
//
//	MD5(method:uri:H(entity-body))
//
// entityBodyHash is the hex MD5 of the request body (Digest-Entity-Body-Hash).
func digestComputeHA2AuthInt(method, uri, entityBodyHash string) string {
	return md5Hex(method, uri, entityBodyHash)
}

// digestComputeResponse computes the expected request-digest (Digest-Response).
//
// qop must be "auth", "auth-int", or "" (empty = RFC 2069 compat: no nc/cnonce).
//
//   - qop=""    → MD5(ha1:nonce:ha2)
//   - otherwise → MD5(ha1:nonce:nc:cnonce:qop:ha2)
func digestComputeResponse(ha1, nonce, nc, cnonce, qop, ha2 string) string {
	if qop == "" {
		return md5Hex(ha1, nonce, ha2)
	}
	return md5Hex(ha1, nonce, nc, cnonce, qop, ha2)
}

// digestComputeResponseAuth computes the server's rspauth for the
// Authentication-Info header (Digest-Response-Auth attr 106).
//
// Identical to digestComputeResponse but H(A2) uses an empty method:
//
//	HA2 = MD5("":uri)
func digestComputeResponseAuth(ha1, nonce, nc, cnonce, qop, uri string) string {
	return digestComputeResponse(ha1, nonce, nc, cnonce, qop, md5Hex("", uri))
}
