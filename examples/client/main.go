package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/sergle/radius/v2"
)

func main() {
	dictPath := flag.String("dict", os.Getenv("RADIUS_DICT"), "Path to RADIUS dictionary file")
	addr := flag.String("addr", "127.0.0.1:1812", "RADIUS server address")
	secretFile := flag.String("secret-file", "", "File with the RADIUS shared secret (default: $RADIUS_SECRET)")
	user := flag.String("user", "a", "Username for Access-Request")
	reqType := flag.String("type", "auth", "Request type: 'auth' (Access-Request) or 'disc' (Disconnect-Request)")
	flag.Parse()
	secret := readSecret(*secretFile)

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

	client := radius.NewRadClient(*addr, secret)

	// Example of using a RequestTemplate (Prepared Statement)
	// This pre-resolves attribute IDs and types once.
	authTemplate, err := dict.CreateRequestTemplate(radius.AccessRequest, "User-Name", "User-Password")
	if err != nil {
		log.Fatalf("Failed to create auth template: %v", err)
	}

	discTemplate, err := dict.CreateRequestTemplate(radius.DisconnectRequest, "Acct-Session-Id", "NAS-IP-Address")
	if err != nil {
		log.Fatalf("Failed to create disc template: %v", err)
	}

	var request *radius.Packet
	switch *reqType {
	case "auth":
		// Use the template to create a request with specific values
		request = authTemplate.CreateRequest(client, *user, readPassword())
		log.Printf("Created Access-Request (via template) for user: %s", *user)
	case "disc":
		// Use the template to create a request with specific values
		request = discTemplate.CreateRequest(client, "100500", "10.8.10.3")
		log.Println("Created Disconnect-Request (via template)")
	default:
		log.Fatalf("Unknown request type: %s", *reqType)
	}

	log.Printf("Sending request to %s...", *addr)
	reply, err := client.Send(request)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}

	log.Printf("Received reply:\n%s", reply.StringMasked())
}

// readSecret returns the shared secret from file, else $RADIUS_SECRET. It's not a
// flag, so it stays out of ps output and shell history, and has no default.
func readSecret(file string) string {
	s := os.Getenv("RADIUS_SECRET")
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Failed to read secret: %v", err)
		}
		s = strings.TrimSpace(string(b))
	}
	if s == "" {
		log.Fatal("Set RADIUS_SECRET or -secret-file")
	}
	return s
}

// readPassword returns $RADIUS_PASSWORD; not a flag, so it stays out of ps output and shell history.
func readPassword() string {
	p := os.Getenv("RADIUS_PASSWORD")
	if p == "" {
		log.Fatal("Set RADIUS_PASSWORD")
	}
	return p
}
