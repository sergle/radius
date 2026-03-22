package radius

// RFC 5090 - RADIUS Extension for Digest Authentication
//
// Digest Authentication is a challenge-response protocol used by HTTP and SIP.
// A NAS (RADIUS client) acting as an HTTP/SIP proxy forwards the Digest
// credentials from the client to the RADIUS server for centralized verification.
//
// Typical Access-Request flow:
//
//  1. NAS sends Access-Request with Digest-Method + Digest-URI (no nonce yet).
//  2. RADIUS returns Access-Challenge with Digest-Nonce + Digest-Realm etc.
//  3. NAS challenges the HTTP/SIP client (401/407).
//  4. Client computes Digest-Response and retransmits.
//  5. NAS sends Access-Request with all Digest-* attributes.
//  6. RADIUS verifies, returns Access-Accept with Digest-Response-Auth.

import (
	"strings"
)

// ── DigestAuthRequest ────────────────────────────────────────────────────────

// DigestAuthRequest wraps an incoming Access-Request packet that carries RFC 5090
// Digest Authentication attributes, providing typed getters for each field.
//
// It is the entry point for RADIUS server handlers processing Digest auth.
// Use IsNonceRequest to distinguish the two-round flow, then construct
// the appropriate reply via Challenge, Accept, or Reject.
type DigestAuthRequest struct {
	p *Packet
}

// NewDigestAuthRequest wraps p for reading its RFC 5090 Digest attributes.
func NewDigestAuthRequest(p *Packet) *DigestAuthRequest {
	return &DigestAuthRequest{p: p}
}

// IsNonceRequest reports whether the packet is a bare nonce-request:
// Digest-Method is present but Digest-Nonce is absent.
// The RADIUS server should respond with Access-Challenge containing a fresh nonce.
func (r *DigestAuthRequest) IsNonceRequest() bool {
	return r.Nonce() == "" && r.Method() != ""
}

// Username returns User-Name (attr 1) used for credential lookup.
// Per RFC 5090 §2.2.2 the server looks up credentials using User-Name,
// not DigestUsername.
func (r *DigestAuthRequest) Username() string { return digestStr(r.p, AttrUserName) }

// State returns the State attribute bytes, or nil if absent.
// The NAS copies State from the Access-Challenge into the follow-up
// Access-Request so the server can correlate the two rounds.
func (r *DigestAuthRequest) State() []byte {
	avp := r.p.GetAVP(AttrState)
	if avp == nil {
		return nil
	}
	v := make([]byte, len(avp.Value))
	copy(v, avp.Value)
	return v
}

// Response returns Digest-Response (103), the hex digest from the client.
func (r *DigestAuthRequest) Response() string { return digestStr(r.p, AttrDigestResponse) }

// Realm returns Digest-Realm (104).
func (r *DigestAuthRequest) Realm() string { return digestStr(r.p, AttrDigestRealm) }

// Nonce returns Digest-Nonce (105).
func (r *DigestAuthRequest) Nonce() string { return digestStr(r.p, AttrDigestNonce) }

// Method returns Digest-Method (108), e.g. "INVITE" or "GET".
func (r *DigestAuthRequest) Method() string { return digestStr(r.p, AttrDigestMethod) }

// URI returns Digest-URI (109).
func (r *DigestAuthRequest) URI() string { return digestStr(r.p, AttrDigestURI) }

// Qop returns Digest-Qop (110), e.g. "auth" or "auth-int".
func (r *DigestAuthRequest) Qop() string { return digestStr(r.p, AttrDigestQop) }

// Algorithm returns Digest-Algorithm (111).
// Defaults to "MD5" when the attribute is absent, per RFC 5090 §3.
func (r *DigestAuthRequest) Algorithm() string {
	return digestStr(r.p, AttrDigestAlgorithm, "MD5")
}

// EntityBodyHash returns Digest-Entity-Body-Hash (112), hex H(entity-body).
// Present only when qop=auth-int.
func (r *DigestAuthRequest) EntityBodyHash() string {
	return digestStr(r.p, AttrDigestEntityBodyHash)
}

// CNonce returns Digest-CNonce (113), the client nonce.
func (r *DigestAuthRequest) CNonce() string { return digestStr(r.p, AttrDigestCNonce) }

// NonceCount returns Digest-Nonce-Count (114) as an 8-char hex string, e.g. "00000001".
func (r *DigestAuthRequest) NonceCount() string { return digestStr(r.p, AttrDigestNonceCount) }

// DigestUsername returns Digest-Username (115).
// This is the username used in the HA1 digest calculation. Credential lookup
// must use Username() (User-Name attr) instead.
func (r *DigestAuthRequest) DigestUsername() string { return digestStr(r.p, AttrDigestUsername) }

// Opaque returns Digest-Opaque (116).
func (r *DigestAuthRequest) Opaque() string { return digestStr(r.p, AttrDigestOpaque) }

// AuthParams returns all Digest-Auth-Param (117) values.
// Each is a full "name=value" pair for extension parameters.
func (r *DigestAuthRequest) AuthParams() []string {
	return allDigestStr(r.p, AttrDigestAuthParam)
}

// AKAAuts returns Digest-AKA-Auts (118), the re-sync token for Digest AKA.
func (r *DigestAuthRequest) AKAAuts() string { return digestStr(r.p, AttrDigestAKAAuts) }

// SIPAOR returns SIP-AOR (122), the SIP Address-of-Record being authenticated.
func (r *DigestAuthRequest) SIPAOR() string { return digestStr(r.p, AttrSIPAOR) }

// Verify reports whether the Digest-Response in the packet is valid for the
// given ha1 (hex H(A1), e.g. pre-stored or computed for the relevant algorithm).
// Returns false if any required attribute is missing.
func (r *DigestAuthRequest) Verify(ha1 string) bool {
	if r.Response() == "" || r.Nonce() == "" || r.Method() == "" || r.URI() == "" {
		return false
	}

	var ha2 string
	switch strings.ToLower(r.Qop()) {
	case "auth-int":
		if r.EntityBodyHash() == "" {
			return false
		}
		ha2 = digestComputeHA2AuthInt(r.Method(), r.URI(), r.EntityBodyHash())
	default:
		ha2 = digestComputeHA2Auth(r.Method(), r.URI())
	}

	expected := digestComputeResponse(ha1, r.Nonce(), r.NonceCount(), r.CNonce(), r.Qop(), ha2)
	return strings.EqualFold(expected, r.Response())
}

// digestComputeResponseAuth verifies the request against password and, if valid,
// returns the rspauth value for the Authentication-Info header (Access-Accept).
// Returns "" if verification fails, so callers can use a nil-like check.
func (r *DigestAuthRequest) digestComputeResponseAuth(password string) string {
	ha1 := digestComputeHA1(r.DigestUsername(), r.Realm(), password)
	if !r.Verify(ha1) {
		return ""
	}
	return digestComputeResponseAuth(ha1, r.Nonce(), r.NonceCount(), r.CNonce(), r.Qop(), r.URI())
}

// Challenge constructs an Access-Challenge DigestAuthResponse with the required
// fields pre-populated: Nonce, Realm, Qop ("auth"), Algorithm ("MD5"), and
// State (set to nonce bytes per RFC 5090 §5 note [4]).
// Use the setter methods to override or add optional fields (e.g. SetOpaque, AddDomain).
func (r *DigestAuthRequest) Challenge(realm, nonce string) *DigestAuthResponse {
	return (&DigestAuthResponse{p: r.p.replyWithCode(AccessChallenge)}).
		SetRealm(realm).
		SetNonce(nonce).
		SetQop("auth").
		SetAlgorithm("MD5").
		SetState([]byte(nonce))
}

// Accept constructs an Access-Accept DigestAuthResponse from this request.
// rspauth is the Digest-Response-Auth value (required for qop=auth; pass ""
// when qop=auth-int, where SetHA1 is used instead, or when qop is absent).
func (r *DigestAuthRequest) Accept(rspauth string) *DigestAuthResponse {
	resp := &DigestAuthResponse{p: r.p.replyWithCode(AccessAccept)}
	if rspauth != "" {
		resp.SetResponseAuth(rspauth)
	}
	return resp
}

// Reject constructs an Access-Reject DigestAuthResponse from this request.
func (r *DigestAuthRequest) Reject() *DigestAuthResponse {
	return &DigestAuthResponse{p: r.p.replyWithCode(AccessReject)}
}

// ── DigestAuthResponse ───────────────────────────────────────────────────────

// DigestAuthResponse builds an RFC 5090 reply packet.
// Obtain one via DigestAuthRequest.Challenge, Accept, or Reject.
// All setter methods return the receiver for fluent chaining.
// Call Packet to retrieve the finished reply.
type DigestAuthResponse struct {
	p *Packet
}

// Packet returns the fully constructed reply packet, ready for returning from
// a RADIUS server handler.
func (r *DigestAuthResponse) Packet() *Packet { return r.p }

// ── Access-Challenge setters ─────────────────────────────────────────────────

// SetNonce sets Digest-Nonce (105). Required in Access-Challenge.
func (r *DigestAuthResponse) SetNonce(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestNonce, v)
	return r
}

// SetRealm sets Digest-Realm (104). Required in Access-Challenge.
func (r *DigestAuthResponse) SetRealm(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestRealm, v)
	return r
}

// SetQop sets a single Digest-Qop (110), replacing any prior values.
// Use AddQop when the challenge should advertise multiple supported options.
func (r *DigestAuthResponse) SetQop(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestQop, v)
	return r
}

// AddQop appends a Digest-Qop (110) value.
// Multiple Qop attributes may appear in Access-Challenge.
func (r *DigestAuthResponse) AddQop(v string) *DigestAuthResponse {
	addDigestStr(r.p, AttrDigestQop, v)
	return r
}

// SetAlgorithm sets Digest-Algorithm (111), e.g. "MD5" or "MD5-sess".
func (r *DigestAuthResponse) SetAlgorithm(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestAlgorithm, v)
	return r
}

// SetOpaque sets Digest-Opaque (116).
func (r *DigestAuthResponse) SetOpaque(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestOpaque, v)
	return r
}

// SetStale sets Digest-Stale (120) to "true" or "false".
// Indicates whether the client's nonce was stale but the credentials are otherwise valid.
func (r *DigestAuthResponse) SetStale(stale bool) *DigestAuthResponse {
	v := "false"
	if stale {
		v = "true"
	}
	setDigestStr(r.p, AttrDigestStale, v)
	return r
}

// AddDomain appends a Digest-Domain (119) URI, defining a protection space component.
// Multiple Domain attributes may appear in Access-Challenge.
func (r *DigestAuthResponse) AddDomain(v string) *DigestAuthResponse {
	addDigestStr(r.p, AttrDigestDomain, v)
	return r
}

// SetState sets the State attribute (24).
// State MUST be present in Access-Challenge (RFC 5090 §5 note [4]) and
// MUST be copied back by the NAS in the follow-up Access-Request.
func (r *DigestAuthResponse) SetState(v []byte) *DigestAuthResponse {
	r.p.SetAVP(AVP{Type: AttrState, Value: v})
	return r
}

// ── Access-Accept setters ────────────────────────────────────────────────────

// SetResponseAuth sets Digest-Response-Auth (106), the server's rspauth value.
// MUST be included in Access-Accept when qop=auth; the NAS puts it in the
// Authentication-Info rspauth directive.
// MUST NOT be sent when qop=auth-int — use SetHA1 instead.
func (r *DigestAuthResponse) SetResponseAuth(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestResponseAuth, v)
	return r
}

// SetNextnonce sets Digest-Nextnonce (107), pre-supplying a nonce for the
// client's next request via the Authentication-Info nextnonce directive.
func (r *DigestAuthResponse) SetNextnonce(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestNextnonce, v)
	return r
}

// SetHA1 sets Digest-HA1 (121), the hex H(A1) value.
// Used in Access-Accept when qop=auth-int so the NAS can compute rspauth locally.
// MUST NOT be sent when qop=auth — use SetResponseAuth instead.
func (r *DigestAuthResponse) SetHA1(v string) *DigestAuthResponse {
	setDigestStr(r.p, AttrDigestHA1, v)
	return r
}

// ── Shared setters ───────────────────────────────────────────────────────────

// AddAuthParam appends a Digest-Auth-Param (117) extension value.
// Valid in Access-Request, Access-Challenge, Access-Accept, and Accounting-Request.
func (r *DigestAuthResponse) AddAuthParam(v string) *DigestAuthResponse {
	addDigestStr(r.p, AttrDigestAuthParam, v)
	return r
}

