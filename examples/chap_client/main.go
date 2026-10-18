package main

import (
	"crypto/rand"
	"flag"
	"log"
	"os"

	"github.com/sergle/radius/v2"
)

func main() {
	dictPath := flag.String("dict", os.Getenv("RADIUS_DICT"), "Path to RADIUS dictionary file")
	addr := flag.String("addr", "127.0.0.1:1812", "RADIUS server address")
	secret := flag.String("secret", "gopher", "RADIUS shared secret")
	user := flag.String("user", "a", "Username for Access-Request")
	pass := flag.String("pass", "a", "Password for CHAP")
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
	radius.SetDefaultDictionary(dict) // used by StringMasked

	client := radius.NewRadClient(*addr, *secret)

	// CHAP request (Access-Request)
	req := client.NewRequest(radius.AccessRequest)
	req.AddAVP(radius.AVP{Type: radius.AttrUserName, Value: []byte(*user)})

	chapID := uint8(1)
	challenge := make([]byte, 16) // RFC 2865: 5..253 bytes, random
	if _, err := rand.Read(challenge); err != nil {
		log.Fatal(err)
	}
	if err := req.SetCHAPPasswordFromSecret(chapID, *pass, challenge); err != nil {
		log.Fatalf("Failed to set CHAP attributes: %v", err)
	}

	log.Printf("Sending CHAP Access-Request to %s...", *addr)
	reply, err := client.Send(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}

	log.Printf("Received reply:\n%s", reply.StringMasked())
}
