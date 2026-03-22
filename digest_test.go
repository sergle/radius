package radius

// Tests for RFC 5090 Digest Authentication support.
//
// Integration test actors:
//
//	SIP UA  ──channels──►  NAS goroutine  ──UDP RADIUS──►  RADIUS Server
//
// The SIP UA and NAS communicate via Go channels (simulating SIP messages).
// The NAS and RADIUS server communicate via real UDP using RadClient/Server.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ── Golden-value unit tests ──────────────────────────────────────────────────

// RFC 2617 §3.5 test vector.
func TestDigestComputeHA1_RFC2617(t *testing.T) {
	got := digestComputeHA1("Mufasa", "testrealm@host.com", "Circle Of Life")
	want := "939e7578ed9e3c518a452acee763bce9"
	if got != want {
		t.Fatalf("HA1 mismatch\n got:  %s\n want: %s", got, want)
	}
}

func TestDigestComputeResponse_RFC2617(t *testing.T) {
	ha1 := "939e7578ed9e3c518a452acee763bce9" // from RFC 2617
	ha2 := digestComputeHA2Auth("GET", "/dir/index.html")

	got := digestComputeResponse(
		ha1,
		"dcd98b7102dd2f0e8b11d0f600bfb0c093", // nonce
		"00000001",                           // nc
		"0a4f113b",                           // cnonce
		"auth",                               // qop
		ha2,
	)
	want := "6629fae49393a05397450978507c4ef1"
	if got != want {
		t.Fatalf("response mismatch\n got:  %s\n want: %s", got, want)
	}
}

func TestDigestComputeResponseNoQop(t *testing.T) {
	// qop="" triggers RFC 2069 compat: MD5(ha1:nonce:ha2)
	ha1 := digestComputeHA1("user", "realm", "pass")
	ha2 := digestComputeHA2Auth("GET", "/resource")
	nonce := "abc123"

	got := digestComputeResponse(ha1, nonce, "", "", "", ha2)
	want := md5Hex(ha1, nonce, ha2)
	if got != want {
		t.Fatalf("no-qop response mismatch: got %s want %s", got, want)
	}
}

func TestDigestResponseAuthDiffersFromRequestDigest(t *testing.T) {
	ha1 := digestComputeHA1("user", "realm.example", "pw")
	nonce, nc, cnonce, qop, uri, method := "nonce42", "00000001", "clientnonce", "auth", "/resource", "GET"

	ha2req := digestComputeHA2Auth(method, uri)
	reqDigest := digestComputeResponse(ha1, nonce, nc, cnonce, qop, ha2req)
	rspauth := digestComputeResponseAuth(ha1, nonce, nc, cnonce, qop, uri)

	// rspauth uses H("":uri) so it must differ from the request digest.
	if reqDigest == rspauth {
		t.Fatal("rspauth must differ from request digest")
	}
}

// ── DigestAuthRequest unit tests ─────────────────────────────────────────────

func TestDigestAuthRequest_Verify(t *testing.T) {
	ha1 := digestComputeHA1("alice", "example.com", "secret")
	ha2 := digestComputeHA2Auth("INVITE", "sip:bob@example.com")
	nonce, nc, cnonce, qop := "testnonce", "00000001", "clientnonce", "auth"

	response := digestComputeResponse(ha1, nonce, nc, cnonce, qop, ha2)

	p := &Packet{}
	p.AddAVP(
		AVP{Type: AttrDigestResponse, Value: []byte(response)},
		AVP{Type: AttrDigestNonce, Value: []byte(nonce)},
		AVP{Type: AttrDigestMethod, Value: []byte("INVITE")},
		AVP{Type: AttrDigestURI, Value: []byte("sip:bob@example.com")},
		AVP{Type: AttrDigestQop, Value: []byte(qop)},
		AVP{Type: AttrDigestNonceCount, Value: []byte(nc)},
		AVP{Type: AttrDigestCNonce, Value: []byte(cnonce)},
	)

	req := NewDigestAuthRequest(p)

	if !req.Verify(ha1) {
		t.Fatal("Verify returned false for a valid response")
	}
	if req.Verify(digestComputeHA1("alice", "example.com", "wrongpass")) {
		t.Fatal("Verify returned true for wrong password")
	}
}

func TestDigestAuthRequest_IsNonceRequest(t *testing.T) {
	// Method present, no nonce → nonce request
	p := &Packet{}
	p.AddAVP(AVP{Type: AttrDigestMethod, Value: []byte("INVITE")})
	if !NewDigestAuthRequest(p).IsNonceRequest() {
		t.Fatal("expected IsNonceRequest=true")
	}

	// Both method and nonce present → auth request
	p.AddAVP(AVP{Type: AttrDigestNonce, Value: []byte("abc")})
	if NewDigestAuthRequest(p).IsNonceRequest() {
		t.Fatal("expected IsNonceRequest=false when nonce is present")
	}
}

func TestDigestAuthRequest_AlgorithmDefault(t *testing.T) {
	// No Digest-Algorithm → must default to "MD5" per RFC 5090.
	if got := NewDigestAuthRequest(&Packet{}).Algorithm(); got != "MD5" {
		t.Fatalf("expected default MD5, got %q", got)
	}
}

func TestDigestAuthRequest_State(t *testing.T) {
	p := &Packet{}
	p.AddAVP(AVP{Type: AttrState, Value: []byte("session-cookie")})
	req := NewDigestAuthRequest(p)

	got := req.State()
	if string(got) != "session-cookie" {
		t.Fatalf("got %q want %q", got, "session-cookie")
	}
	// Must be a copy.
	got[0] = 'X'
	if string(req.State()) != "session-cookie" {
		t.Fatal("State() returned a reference instead of a copy")
	}
}

// ── DigestAuthResponse unit tests ────────────────────────────────────────────

func TestDigestAuthResponse_ChallengeFields(t *testing.T) {
	req := NewDigestAuthRequest(&Packet{Secret: "s"})
	resp := req.Challenge("example.com", "mynonce").
		SetOpaque("opaquevalue").
		SetStale(true).
		AddDomain("sip:example.com").
		AddDomain("sip:backup.example.com").
		SetState([]byte("correlationkey"))

	p := resp.Packet()
	if p.Code != AccessChallenge {
		t.Fatalf("expected AccessChallenge, got %s", p.Code)
	}
	if digestStr(p, AttrDigestNonce) != "mynonce" {
		t.Error("nonce mismatch")
	}
	if digestStr(p, AttrDigestRealm) != "example.com" {
		t.Error("realm mismatch")
	}
	if digestStr(p, AttrDigestQop) != "auth" {
		t.Error("qop mismatch")
	}
	if digestStr(p, AttrDigestAlgorithm) != "MD5" {
		t.Error("algorithm mismatch")
	}
	if digestStr(p, AttrDigestOpaque) != "opaquevalue" {
		t.Error("opaque mismatch")
	}
	if digestStr(p, AttrDigestStale) != "true" {
		t.Error("stale mismatch")
	}
	domains := allDigestStr(p, AttrDigestDomain)
	if len(domains) != 2 || domains[0] != "sip:example.com" {
		t.Errorf("domains mismatch: %v", domains)
	}
	stateAVP := p.GetAVP(AttrState)
	if stateAVP == nil || string(stateAVP.Value) != "correlationkey" {
		t.Error("state mismatch")
	}
}

func TestDigestAuthResponse_MultipleQops(t *testing.T) {
	req := NewDigestAuthRequest(&Packet{Secret: "s"})
	resp := req.Challenge("", "").AddQop("auth-int")

	qops := allDigestStr(resp.Packet(), AttrDigestQop)
	if len(qops) != 2 || qops[0] != "auth" || qops[1] != "auth-int" {
		t.Fatalf("unexpected qop values: %v", qops)
	}
}

func TestDigestAuthResponse_AcceptFields(t *testing.T) {
	req := NewDigestAuthRequest(&Packet{Secret: "s"})
	resp := req.Accept("rspauth-hex").
		SetNextnonce("nextnonce-value").
		AddAuthParam(`charset="UTF-8"`)

	p := resp.Packet()
	if p.Code != AccessAccept {
		t.Fatalf("expected AccessAccept, got %s", p.Code)
	}
	if digestStr(p, AttrDigestResponseAuth) != "rspauth-hex" {
		t.Error("response-auth mismatch")
	}
	if digestStr(p, AttrDigestNextnonce) != "nextnonce-value" {
		t.Error("nextnonce mismatch")
	}
	params := allDigestStr(p, AttrDigestAuthParam)
	if len(params) != 1 || params[0] != `charset="UTF-8"` {
		t.Errorf("auth-param mismatch: %v", params)
	}
}

func TestDigestAuthResponse_RejectCode(t *testing.T) {
	req := NewDigestAuthRequest(&Packet{Secret: "s"})
	if req.Reject().Packet().Code != AccessReject {
		t.Fatal("expected AccessReject")
	}
}

func TestDigestAuthResponse_SetStale(t *testing.T) {
	req := NewDigestAuthRequest(&Packet{Secret: "s"})

	resp := req.Challenge("", "").SetStale(true)
	if digestStr(resp.Packet(), AttrDigestStale) != "true" {
		t.Fatal("expected stale=true")
	}
	resp.SetStale(false)
	if digestStr(resp.Packet(), AttrDigestStale) != "false" {
		t.Fatal("expected stale=false")
	}
}

// ── Integration test helpers ─────────────────────────────────────────────────

// sipInvite represents a SIP INVITE message passed from the SIP UA to the NAS.
type sipInvite struct {
	Username string
	Method   string
	URI      string
	// Digest fields — empty on the first unauthenticated request.
	Realm     string
	Nonce     string
	NC        string
	CNonce    string
	Qop       string
	Algorithm string
	Response  string
}

// sipResult represents the NAS response back to the SIP UA.
type sipResult struct {
	Code         int    // 407=challenge, 200=OK, 401=rejected
	Realm        string // populated on 407
	Nonce        string // populated on 407
	Qop          string // populated on 407
	Algorithm    string // populated on 407
	ResponseAuth string // rspauth, populated on 200
}

func newTestNonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// startRadiusServer starts a RADIUS server implementing RFC 5090 Digest auth.
// The handler uses DigestAuthRequest/DigestAuthResponse for the full two-round flow.
func startRadiusServer(t *testing.T, realm string, users map[string]string, secret string) string {
	t.Helper()

	var mu sync.Mutex
	validNonces := map[string]bool{}

	handler := HandlerFunc(func(ctx context.Context, raw *Packet) *Packet {
		req := NewDigestAuthRequest(raw)

		if req.IsNonceRequest() {
			// ── Round 1: issue challenge ─────────────────────────────────────
			nonce := newTestNonce()
			mu.Lock()
			validNonces[nonce] = true
			mu.Unlock()

			return req.Challenge(realm, nonce).Packet()
		}

		// ── Round 2: verify credentials ──────────────────────────────────────
		mu.Lock()
		nonceOK := validNonces[req.Nonce()]
		if nonceOK {
			delete(validNonces, req.Nonce()) // single-use
		}
		mu.Unlock()

		if !nonceOK {
			return req.Reject().Packet()
		}

		// Credential lookup uses User-Name, not Digest-Username (RFC 5090 §2.2.2).
		pw, ok := users[req.Username()]
		if !ok {
			return req.Reject().Packet()
		}

		rspauth := req.digestComputeResponseAuth(pw)
		if rspauth == "" {
			return req.Reject().Packet()
		}
		return req.Accept(rspauth).Packet()
	})

	srvCtx, cancel := context.WithCancel(context.Background())
	srv := NewServer("127.0.0.1:0", secret, handler)
	srv.ctx = srvCtx
	srv.cancel = cancel

	go srv.ListenAndServe()
	t.Cleanup(cancel)

	for i := 0; i < 20; i++ {
		if srv.conn != nil {
			return srv.conn.LocalAddr().String()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("RADIUS server failed to bind")
	return ""
}

// ── Full flow integration test ───────────────────────────────────────────────

func TestDigestAuthIntegration(t *testing.T) {
	const (
		realm    = "example.com"
		username = "alice"
		password = "s3cr3t!"
		sipURI   = "sip:bob@example.com"
		method   = "INVITE"
		secret   = "radius-secret"
	)

	radiusAddr := startRadiusServer(t, realm,
		map[string]string{username: password}, secret)

	nas := NewRadClient(radiusAddr, secret)
	nas.SetTimeout(2 * time.Second)

	// runFlow drives one full challenge-response cycle.
	// pw is what the SIP UA uses to compute its Digest-Response.
	// Returns the final sipResult and the nonce from the challenge
	// (needed by the caller to independently verify rspauth).
	runFlow := func(pw string) (sipResult, string, error) {
		uaToNAS := make(chan sipInvite, 1)
		nasToUA := make(chan sipResult, 1)

		var nasErr error

		// ── NAS goroutine ─────────────────────────────────────────────────────
		go func() {
			invite := <-uaToNAS

			// ── RADIUS round 1: request a nonce ──────────────────────────────
			req1 := nas.NewAccessRequest()
			req1.AddAVP(
				AVP{Type: AttrUserName, Value: []byte(invite.Username)},
				AVP{Type: AttrDigestMethod, Value: []byte(invite.Method)},
				AVP{Type: AttrDigestURI, Value: []byte(invite.URI)},
			)

			reply1, err := nas.Send(req1)
			if err != nil {
				nasErr = fmt.Errorf("nonce request failed: %w", err)
				nasToUA <- sipResult{Code: http.StatusInternalServerError}
				return
			}
			if reply1.Code != AccessChallenge {
				nasErr = fmt.Errorf("expected Access-Challenge, got %s", reply1.Code)
				nasToUA <- sipResult{Code: http.StatusInternalServerError}
				return
			}

			// Read challenge attributes via DigestAuthRequest (used as a reader here).
			ch := NewDigestAuthRequest(reply1)
			state := ch.State()

			// Forward 407 Proxy Authentication Required to SIP UA.
			nasToUA <- sipResult{
				Code:      http.StatusProxyAuthRequired,
				Realm:     ch.Realm(),
				Nonce:     ch.Nonce(),
				Qop:       ch.Qop(),
				Algorithm: ch.Algorithm(),
			}

			// Receive authenticated INVITE from SIP UA.
			authInvite := <-uaToNAS

			// ── RADIUS round 2: forward credentials ──────────────────────────
			req2 := nas.NewAccessRequest()
			req2.AddAVP(
				AVP{Type: AttrUserName, Value: []byte(authInvite.Username)},
				AVP{Type: AttrDigestResponse, Value: []byte(authInvite.Response)},
				AVP{Type: AttrDigestRealm, Value: []byte(authInvite.Realm)},
				AVP{Type: AttrDigestNonce, Value: []byte(authInvite.Nonce)},
				AVP{Type: AttrDigestMethod, Value: []byte(authInvite.Method)},
				AVP{Type: AttrDigestURI, Value: []byte(authInvite.URI)},
				AVP{Type: AttrDigestQop, Value: []byte(authInvite.Qop)},
				AVP{Type: AttrDigestAlgorithm, Value: []byte(authInvite.Algorithm)},
				AVP{Type: AttrDigestCNonce, Value: []byte(authInvite.CNonce)},
				AVP{Type: AttrDigestNonceCount, Value: []byte(authInvite.NC)},
				AVP{Type: AttrDigestUsername, Value: []byte(authInvite.Username)},
				AVP{Type: AttrSIPAOR, Value: []byte("sip:" + authInvite.Username + "@" + authInvite.Realm)},
			)
			// RFC 5090 §5 note [4]: copy State from the Access-Challenge.
			if state != nil {
				req2.AddAVP(AVP{Type: AttrState, Value: state})
			}

			reply2, err := nas.Send(req2)
			if err != nil {
				nasErr = fmt.Errorf("auth request failed: %w", err)
				nasToUA <- sipResult{Code: http.StatusInternalServerError}
				return
			}

			switch reply2.Code {
			case AccessAccept:
				nasToUA <- sipResult{
					Code:         http.StatusOK,
					ResponseAuth: string(reply2.GetAVP(AttrDigestResponseAuth).Value),
				}
			case AccessReject:
				nasToUA <- sipResult{Code: http.StatusUnauthorized}
			default:
				nasToUA <- sipResult{Code: http.StatusInternalServerError}
			}
		}()

		// ── SIP UA ────────────────────────────────────────────────────────────
		// Step 1: send unauthenticated INVITE.
		uaToNAS <- sipInvite{Username: username, Method: method, URI: sipURI}

		// Receive 407 Proxy Authentication Required.
		challenge := <-nasToUA
		if challenge.Code != http.StatusProxyAuthRequired {
			return sipResult{}, "", fmt.Errorf("expected %d, got %d", http.StatusProxyAuthRequired, challenge.Code)
		}

		// Compute Digest-Response per RFC 2617.
		cnonce := "ua-client-nonce"
		nc := "00000001"
		ha1 := digestComputeHA1(username, challenge.Realm, pw)
		ha2 := digestComputeHA2Auth(method, sipURI)
		response := digestComputeResponse(ha1, challenge.Nonce, nc, cnonce, challenge.Qop, ha2)

		// Step 2: retransmit with credentials.
		uaToNAS <- sipInvite{
			Username: username, Method: method, URI: sipURI,
			Realm: challenge.Realm, Nonce: challenge.Nonce,
			NC: nc, CNonce: cnonce, Qop: challenge.Qop,
			Algorithm: challenge.Algorithm, Response: response,
		}

		result := <-nasToUA
		if nasErr != nil {
			return sipResult{}, "", nasErr
		}
		return result, challenge.Nonce, nil
	}

	t.Run("correct password: 200 OK with valid rspauth", func(t *testing.T) {
		result, nonce, err := runFlow(password)
		if err != nil {
			t.Fatalf("flow error: %v", err)
		}
		if result.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", result.Code)
		}
		if result.ResponseAuth == "" {
			t.Fatal("expected Digest-Response-Auth in Access-Accept, got empty")
		}

		// SIP UA independently verifies rspauth (Authentication-Info: rspauth=...).
		ha1 := digestComputeHA1(username, realm, password)
		expected := digestComputeResponseAuth(ha1, nonce, "00000001", "ua-client-nonce", "auth", sipURI)
		if result.ResponseAuth != expected {
			t.Errorf("rspauth mismatch\n got:  %s\n want: %s", result.ResponseAuth, expected)
		}
	})

	t.Run("wrong password: 401 Unauthorized", func(t *testing.T) {
		result, _, err := runFlow("wrongpassword")
		if err != nil {
			t.Fatalf("flow error: %v", err)
		}
		if result.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", result.Code)
		}
	})
}
