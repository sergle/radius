package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/sergle/radius/v2"
)

func main() {
	dictPath := flag.String("dict", os.Getenv("RADIUS_DICT"), "Path to RADIUS dictionary file")
	addr := flag.String("addr", "127.0.0.1:1812", "Address to listen on")
	secret := flag.String("secret", "gopher", "RADIUS shared secret")
	flag.Parse()
	if *dictPath == "" {
		defaults := []string{
			"../../dictionary.builtin",
			"./dictionary",
		}
		for _, p := range defaults {
			if _, err := os.Stat(p); err == nil {
				*dictPath = p
				break
			}
		}
	}

	dict := radius.NewDictionary()
	if *dictPath != "" {
		err := dict.LoadFile(*dictPath)
		if err != nil {
			log.Fatalf("Failed to load dictionary from %s: %v", *dictPath, err)
		}
		log.Printf("Loaded dictionary from %s", *dictPath)
	} else {
		log.Println("No dictionary loaded. Some AVP decoding might be limited.")
	}

	// Pre-resolve templates for efficient reuse in handlers
	// These are now local variables, not part of a struct.
	replyMsgTemplate, err := dict.GetTemplate("Reply-Message")
	if err != nil {
		log.Printf("Warning: Reply-Message template failed: %v", err)
	}

	ciscoVsaTemplate, err := dict.GetVSATemplate("Cisco", "h323-remote-address")
	if err != nil {
		log.Printf("Warning: Cisco VSA template failed: %v", err)
	}

	var cnt int64

	// Create the handler as a closure to keep it clean and avoid struct clutter
	handler := radius.HandlerFunc(func(request *radius.Packet) *radius.Packet {
		count := atomic.AddInt64(&cnt, 1)
		log.Printf("[%d] [Authenticate] %s\n", count, request.String())

		for _, avp := range request.AVPs {
			attrName := dict.GetAttributeName(avp.Type)
			attrType := dict.GetAttributeType(attrName)
			log.Printf("  AVP: name=%s type=%s value=%v\n", attrName, attrType, dict.DecodeAVPValue(request, avp))
		}

		npac := request.Reply()
		switch request.Code {
		case radius.AccessRequest:
			if request.GetUsername() == "a" && request.GetPassword() == "a" {
				npac.Code = radius.AccessAccept
				replyMsgTemplate.Add(npac, "Authentication successful")
			} else {
				npac.Code = radius.AccessReject
				replyMsgTemplate.Add(npac, "Authentication failed")
			}
		case radius.AccountingRequest:
			npac.Code = radius.AccountingResponse
		case radius.DisconnectRequest:
			npac.Code = radius.DisconnectAccept
			replyMsgTemplate.Add(npac, "Session disconnected")
			ciscoVsaTemplate.Add(npac, "10.20.30.41")
		default:
			log.Printf("[%d] [WRN] Received unknown packet code: %d\n", count, request.Code)
			return nil
		}

		log.Printf("[%d] Reply: %s\n", count, npac.String())
		return npac
	})

	s := radius.NewServer(*addr, *secret, handler)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error)

	go func() {
		log.Printf("Starting RADIUS server on %s ...", *addr)
		err := s.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()

	select {
	case sig := <-signalChan:
		log.Printf("Received signal %v, stopping server...", sig)
		s.Stop()
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	}
}
