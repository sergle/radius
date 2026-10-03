package radius

import (
	"context"
	"log"
	"testing"
	"time"
)

func TestServerSurvivesMalformedPacketAndPanickingHandler(t *testing.T) {
	secret := "shared-secret"
	dict := GetDefaultDictionary()

	handler := HandlerFunc(func(ctx context.Context, request *Packet) *Packet {
		if request.GetUsername() == "panic" {
			panic("handler bug")
		}
		// Log the request like examples/server does.
		request.EachAVP(func(a AVP) bool {
			log.Printf("AVP: %s", dict.DecodeAVPValue(request, a))
			return true
		})
		log.Print(request.String())
		reply := request.Reply()
		reply.Code = AccessAccept
		return reply
	})

	addr, _ := startTestServer(t, NewServer("127.0.0.1:0", secret, handler))

	client := NewRadClient(addr, secret)
	client.SetTimeout(500 * time.Millisecond)

	sendValid := func(t *testing.T) {
		t.Helper()
		req := client.NewAccessRequest()
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("testuser")})
		reply, err := client.Send(req)
		if err != nil {
			t.Fatalf("valid request after bad one failed: %v", err)
		}
		if reply.Code != AccessAccept {
			t.Fatalf("got %v, want Access-Accept", reply.Code)
		}
	}

	t.Run("malformed attributes", func(t *testing.T) {
		req := client.NewAccessRequest()
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("testuser")})
		req.AddAVP(AVP{Type: AttrSessionTimeout, Value: []byte{1}})
		req.AddAVP(AVP{Type: AttrNASPort, Value: []byte{0, 1}})
		req.AddAVP(AVP{Type: AttrVendorSpecific, Value: []byte{0, 0}})
		reply, err := client.Send(req)
		if err != nil {
			t.Fatalf("malformed request got no reply: %v", err)
		}
		if reply.Code != AccessAccept {
			t.Fatalf("got %v, want Access-Accept", reply.Code)
		}
		sendValid(t)
	})

	t.Run("panicking handler", func(t *testing.T) {
		req := client.NewAccessRequest()
		req.AddAVP(AVP{Type: AttrUserName, Value: []byte("panic")})
		if _, err := client.Send(req); err == nil {
			t.Fatal("expected no reply when handler panics")
		}
		sendValid(t)
	})
}
