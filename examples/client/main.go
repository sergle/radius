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
	pass := flag.String("pass", "a", "Password for Access-Request")
	reqType := flag.String("type", "auth", "Request type: 'auth' (Access-Request) or 'disc' (Disconnect-Request)")
	flag.Parse()

	// Dictionary resolution logic
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
	}

	client := radius.NewRadClient(*addr, *secret)

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
		request = authTemplate.CreateRequest(client, *user, *pass)
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

	log.Printf("Received reply:\n%s", reply.String())
}
