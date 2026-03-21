package radius

// EAP-MSCHAPv2 end-to-end integration test.
//
// Three goroutines simulate the real three-party flow described in RFC 3579:
//
//   Supplicant <──EAP────> NAS <──RADIUS/UDP──> RADIUS server
//
// Supplicant ↔ NAS communicate via Go channels carrying *EapPacket.
// NAS ↔ RADIUS server communicate over real UDP using the library's server
// and RadClient.

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"
)

// ── State attribute ───────────────────────────────────────────────────────────


// ── Integration test ──────────────────────────────────────────────────────────

func TestEAPMSCHAPv2Integration(t *testing.T) {
	const (
		radiusSecret = "shared-secret"
		testUser     = "testuser"
		testPass     = "testpass"
		serverName   = "testserver"
	)

	// ── RADIUS server: per-session state keyed by State AVP ──────────────────
	type eapSession struct {
		serverChallenge []byte
		username        string
	}
	var sessMu sync.Mutex
	sessions := map[string]eapSession{}

	// ── RADIUS server handler ─────────────────────────────────────────────────
	//
	// Round 1: receives EAP-Response/Identity
	//          → sends Access-Challenge with EAP-Request/MSCHAPv2-Challenge + State
	//
	// Round 2: receives EAP-Response/MSCHAPv2-Response + State
	//          → verifies NT-Response
	//          → sends Access-Accept with EAP-Success  (or Access-Reject)
	handler := HandlerFunc(func(ctx context.Context, req *Packet) *Packet {
		eap := req.GetEAPMessage()
		if eap == nil {
			return nil
		}
		reply := req.Reply()

		switch eap.Type {

		case EapTypeIdentity:
			user := string(eap.Data)
			t.Logf("RADIUS[round 1]: identity=%q → sending MSCHAPv2 challenge", user)

			serverChallenge := make([]byte, 16)
			cryptorand.Read(serverChallenge)

			// Use a random state token to correlate the next request
			var tok [8]byte
			cryptorand.Read(tok[:])
			stateKey := fmt.Sprintf("%x", tok)

			sessMu.Lock()
			sessions[stateKey] = eapSession{serverChallenge: serverChallenge, username: user}
			sessMu.Unlock()

			// EAP-Request/MSCHAPv2-Challenge
			// MSCHAPv2 payload: Value-Size(1) + Value(16 bytes) + Name
			challengePayload := make([]byte, 1+16+len(serverName))
			challengePayload[0] = 16 // Value-Size
			copy(challengePayload[1:], serverChallenge)
			copy(challengePayload[17:], serverName)

			baseEap := &EapPacket{Code: EapCodeRequest, Identifier: eap.Identifier + 1, Type: EapTypeMSCHAPV2}
			challengeEap := (&MsChapV2Packet{Eap: baseEap, OpCode: MsChapV2OpCodeChallenge, Data: challengePayload}).ToEap()

			reply.Code = AccessChallenge
			reply.AddAVP(*challengeEap.ToEAPMessage())
			reply.AddAVP(AVP{Type: AttrState, Value: []byte(stateKey)})

		case EapTypeMSCHAPV2:
			t.Log("RADIUS[round 2]: received MSCHAPv2 response → verifying NT-Response")

			mschap, err := MsChapV2PacketFromEap(eap)
			if err != nil || mschap.OpCode != MsChapV2OpCodeResponse {
				t.Logf("RADIUS: bad MSCHAPv2 packet: err=%v opcode=%v", err, mschap.OpCode)
				reply.Code = AccessReject
				return reply
			}

			stateAVP := req.GetAVP(AttrState)
			// mschap.Data layout (RFC 2759):
			//   [0]      Value-Size = 49
			//   [1:17]   Peer-Challenge (16 bytes)
			//   [17:25]  Reserved (8 bytes, zero)
			//   [25:49]  NT-Response (24 bytes)
			//   [49]     Flags
			//   [50:]    Name (username)
			if stateAVP == nil || len(mschap.Data) < 50 {
				reply.Code = AccessReject
				return reply
			}

			sessMu.Lock()
			sess, ok := sessions[string(stateAVP.Value)]
			sessMu.Unlock()
			if !ok {
				t.Log("RADIUS: unknown session state")
				reply.Code = AccessReject
				return reply
			}

			peerChallenge := mschap.Data[1:17]
			ntResp := mschap.Data[25:49]

			expected, err := MSCHAPv2NTResponse(sess.serverChallenge, peerChallenge, sess.username, testPass)
			if err != nil || !bytes.Equal(ntResp, expected) {
				t.Logf("RADIUS: NT-Response mismatch for %q", sess.username)
				reply.Code = AccessReject
				reply.AddAVP(*(&EapPacket{Code: EapCodeFailure, Identifier: eap.Identifier}).ToEAPMessage())
				return reply
			}

			t.Logf("RADIUS[round 2]: NT-Response OK for %q → Access-Accept", sess.username)
			reply.Code = AccessAccept
			reply.AddAVP(*(&EapPacket{Code: EapCodeSuccess, Identifier: eap.Identifier}).ToEAPMessage())
		}
		return reply
	})

	// ── Start RADIUS server ───────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer("127.0.0.1:0", radiusSecret, handler)
	srv.ctx = ctx
	srv.cancel = cancel
	go srv.ListenAndServe()

	var serverAddr string
	for i := 0; i < 20; i++ {
		if srv.conn != nil {
			serverAddr = srv.conn.LocalAddr().String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if serverAddr == "" {
		t.Fatal("RADIUS server failed to start")
	}

	// ── Run sub-tests ─────────────────────────────────────────────────────────
	t.Run("valid credentials", func(t *testing.T) {
		runEAPMSCHAPv2(t, serverAddr, radiusSecret, testUser, testPass, true)
	})
	t.Run("wrong password", func(t *testing.T) {
		runEAPMSCHAPv2(t, serverAddr, radiusSecret, testUser, "wrongpass", false)
	})
}

// runEAPMSCHAPv2 drives the three-party EAP-MSCHAPv2 flow and checks the outcome.
// expectSuccess=true means we expect EAP-Success / Access-Accept.
func runEAPMSCHAPv2(t *testing.T, serverAddr, radiusSecret, username, password string, expectSuccess bool) {
	t.Helper()

	// Channels between Supplicant and NAS
	supToNAS := make(chan *EapPacket, 1)
	nasToSup := make(chan *EapPacket, 1)
	done := make(chan error, 1)

	// ── Supplicant goroutine ──────────────────────────────────────────────────
	//
	// Simulates an end-user device running the EAP state machine:
	//   1. Waits for EAP-Request/Identity from NAS
	//   2. Sends EAP-Response/Identity
	//   3. Waits for EAP-Request/MSCHAPv2-Challenge
	//   4. Computes NT-Response and sends EAP-Response/MSCHAPv2-Response
	//   5. Waits for EAP-Success or EAP-Failure
	go func() {
		// Step 1: EAP-Request/Identity from NAS
		req := <-nasToSup
		if req.Code != EapCodeRequest || req.Type != EapTypeIdentity {
			done <- fmt.Errorf("supplicant: expected Request/Identity, got code=%v type=%v", req.Code, req.Type)
			return
		}
		t.Log("Supplicant: ← EAP-Request/Identity")

		// Step 2: EAP-Response/Identity
		supToNAS <- &EapPacket{
			Code:       EapCodeResponse,
			Identifier: req.Identifier,
			Type:       EapTypeIdentity,
			Data:       []byte(username),
		}
		t.Logf("Supplicant: → EAP-Response/Identity (%q)", username)

		// Step 3: EAP-Request/MSCHAPv2-Challenge
		req = <-nasToSup
		if req.Code != EapCodeRequest || req.Type != EapTypeMSCHAPV2 {
			done <- fmt.Errorf("supplicant: expected Request/MSCHAPv2, got code=%v type=%v", req.Code, req.Type)
			return
		}
		mschap, err := MsChapV2PacketFromEap(req)
		if err != nil || mschap.OpCode != MsChapV2OpCodeChallenge || len(mschap.Data) < 17 {
			done <- fmt.Errorf("supplicant: bad MSCHAPv2 challenge: err=%v", err)
			return
		}
		serverChallenge := mschap.Data[1:17] // skip Value-Size byte
		t.Log("Supplicant: ← EAP-Request/MSCHAPv2-Challenge")

		// Step 4: compute NT-Response and send EAP-Response/MSCHAPv2-Response
		peerChallenge := make([]byte, 16)
		cryptorand.Read(peerChallenge)

		ntResp, err := MSCHAPv2NTResponse(serverChallenge, peerChallenge, username, password)
		if err != nil {
			done <- fmt.Errorf("supplicant: NT-Response computation failed: %v", err)
			return
		}

		// RFC 2759 Response Value:
		//   Value-Size(1=49) + PeerChallenge(16) + Reserved(8) + NT-Response(24) + Flags(1) + Name
		responseData := make([]byte, 1+16+8+24+1+len(username))
		responseData[0] = 49 // Value-Size
		copy(responseData[1:17], peerChallenge)
		// responseData[17:25] = reserved (zeros)
		copy(responseData[25:49], ntResp)
		// responseData[49] = 0 (Flags)
		copy(responseData[50:], username)

		baseEap := &EapPacket{Code: EapCodeResponse, Identifier: req.Identifier, Type: EapTypeMSCHAPV2}
		respEap := (&MsChapV2Packet{Eap: baseEap, OpCode: MsChapV2OpCodeResponse, Data: responseData}).ToEap()
		supToNAS <- respEap
		t.Log("Supplicant: → EAP-Response/MSCHAPv2-Response")

		// Step 5: EAP-Success or EAP-Failure
		result := <-nasToSup
		if expectSuccess && result.Code != EapCodeSuccess {
			done <- fmt.Errorf("supplicant: expected EAP-Success, got code=%v", result.Code)
			return
		}
		if !expectSuccess && result.Code != EapCodeFailure {
			done <- fmt.Errorf("supplicant: expected EAP-Failure, got code=%v", result.Code)
			return
		}
		t.Logf("Supplicant: ← EAP-%v", result.Code)
		done <- nil
	}()

	// ── NAS goroutine ─────────────────────────────────────────────────────────
	//
	// Simulates a Network Access Server (authenticator):
	//   - Initiates EAP with EAP-Request/Identity
	//   - Forwards EAP packets from the supplicant to the RADIUS server
	//   - Forwards EAP packets from RADIUS replies back to the supplicant
	//   - Tracks the RADIUS State attribute across rounds
	go func() {
		radClient := NewRadClient(serverAddr, radiusSecret)
		radClient.SetTimeout(3 * time.Second)

		// Initiate: send EAP-Request/Identity to supplicant
		var idBuf [1]byte
		cryptorand.Read(idBuf[:])
		nasToSup <- &EapPacket{Code: EapCodeRequest, Identifier: idBuf[0], Type: EapTypeIdentity}
		t.Log("NAS: → EAP-Request/Identity to supplicant")

		var currentState []byte // echoed back in each subsequent Access-Request

		for {
			eapFromSup := <-supToNAS
			t.Logf("NAS: received EAP %v/%v from supplicant → forwarding to RADIUS", eapFromSup.Code, eapFromSup.Type)

			req := radClient.NewRequest(AccessRequest)
			req.AddAVP(AVP{Type: AttrUserName, Value: []byte(username)})
			req.AddAVP(*eapFromSup.ToEAPMessage())
			if currentState != nil {
				req.AddAVP(AVP{Type: AttrState, Value: currentState})
			}

			reply, err := radClient.Send(req)
			if err != nil {
				t.Errorf("NAS: RADIUS error: %v", err)
				return
			}
			t.Logf("NAS: RADIUS replied %v", reply.Code)

			eapFromServer := reply.GetEAPMessage()

			switch reply.Code {
			case AccessChallenge:
				if stateAVP := reply.GetAVP(AttrState); stateAVP != nil {
					currentState = append([]byte(nil), stateAVP.Value...)
				}
				if eapFromServer != nil {
					nasToSup <- eapFromServer
				}

			case AccessAccept:
				if eapFromServer != nil {
					nasToSup <- eapFromServer
				} else {
					nasToSup <- &EapPacket{Code: EapCodeSuccess, Identifier: eapFromSup.Identifier}
				}
				return

			case AccessReject:
				if eapFromServer != nil {
					nasToSup <- eapFromServer
				} else {
					nasToSup <- &EapPacket{Code: EapCodeFailure, Identifier: eapFromSup.Identifier}
				}
				return
			}
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("flow failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out")
	}
}
