package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/sergle/radius/v2"
)

func main() {
	dictPath := flag.String("dict", os.Getenv("RADIUS_DICT"), "Path to additional vendor dictionary file (optional)")
	addr := flag.String("addr", "127.0.0.1:1812", "Address to listen on")
	secret := flag.String("secret", "gopher", "RADIUS shared secret")
	flag.Parse()

	dict := radius.NewDictionary()
	if err := dict.LoadBuiltin(); err != nil {
		log.Fatalf("Failed to load built-in dictionary: %v", err)
	}
	if *dictPath != "" {
		if err := dict.LoadFile(*dictPath); err != nil {
			log.Fatalf("Failed to load dictionary from %s: %v", *dictPath, err)
		}
		log.Printf("Loaded dictionary from %s", *dictPath)
	}

	// Pre-resolve a reusable reply template: Reply-Message + Cisco h323-remote-address VSA.
	// Fill() only populates as many slots as values provided, so single-value calls
	// (AccessAccept/Reject) only set Reply-Message; two-value calls (DisconnectAccept) set both.
	replyTemplate, err := dict.CreateRequestTemplate(radius.AccessAccept, "Reply-Message")
	if err != nil {
		log.Printf("Warning: Reply-Message template failed: %v", err)
	}
	if err := replyTemplate.AddVSAAttribute(dict, "Cisco", "h323-remote-address"); err != nil {
		log.Printf("Warning: Cisco VSA template failed: %v", err)
	}

	var cnt int64

	// Create the handler as a closure to keep it clean and avoid struct clutter
	handler := radius.HandlerFunc(func(ctx context.Context, request *radius.Packet) *radius.Packet {
		count := atomic.AddInt64(&cnt, 1)
		log.Printf("[%d] [Authenticate] %s\n", count, request.String())

		for _, avp := range request.AVPs {
			attrName := dict.GetAttributeName(avp.Type)
			attrType := dict.GetAttributeType(attrName)
			log.Printf("  AVP: name=%s type=%s value=%v\n", attrName, attrType, dict.DecodeAVPValue(request, avp))
		}

		switch request.Code {
		case radius.AccessRequest:
			if request.GetUsername() == "a" && request.GetPassword() == "a" {
				npac := request.ReplyAccept()
				replyTemplate.Fill(npac, "Authentication successful")
				return npac
			}
			npac := request.ReplyReject()
			replyTemplate.Fill(npac, "Authentication failed")
			return npac
		case radius.AccountingRequest:
			return request.ReplyAccountingResponse()
		case radius.DisconnectRequest:
			npac := request.ReplyDisconnectAccept()
			replyTemplate.Fill(npac, "Session disconnected", "10.20.30.41")
			log.Printf("[%d] Reply: %s\n", count, npac.String())
			return npac
		default:
			log.Printf("[%d] [WRN] Received unknown packet code: %d\n", count, request.Code)
			return nil
		}
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
