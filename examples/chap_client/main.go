package main

import (
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

	// Dictionary resolution logic (same as examples/client)
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
		if err := dict.LoadFile(*dictPath); err != nil {
			log.Fatalf("Failed to load dictionary from %s: %v", *dictPath, err)
		}
		log.Printf("Loaded dictionary from %s", *dictPath)
	}

	client := radius.NewRadClient(*addr, *secret)

	// CHAP request (Access-Request)
	req := client.NewRequest(radius.AccessRequest)
	req.AddAVP(radius.AVP{Type: radius.AttrUserName, Value: []byte(*user)})

	chapID := uint8(1)
	challenge := []byte("1234567890abcdef") // 16 bytes (RFC2865: 1..16)
	if err := req.SetCHAPPasswordFromSecret(chapID, *pass, challenge); err != nil {
		log.Fatalf("Failed to set CHAP attributes: %v", err)
	}

	log.Printf("Sending CHAP Access-Request to %s...", *addr)
	reply, err := client.Send(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}

	log.Printf("Received reply:\n%s", reply.String())
}

