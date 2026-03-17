a golang radius library (v2)
=============================

[![PkgGoDev](https://pkg.go.dev/badge/radius)](https://pkg.go.dev/radius)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/sergle/radius/blob/master/LICENSE)

A feature-rich RADIUS library for Go. This is a significantly refactored version (v2) of the original library, optimized for clarity and ease of use.

This project forks from https://github.com/bronze1man/radius

## Key Features
- **Simplified API**: Clean and intuitive Go-native interfaces.
- **Dictionary Support**: Full support for FreeRADIUS-style dictionary files.
- **Builtin Dictionary**: Minimal standard attributes included out-of-the-box.
- **Template System**: Pre-resolve attributes and VSAs for packet construction.
- **Lazy Decoding**: Zero-allocation iterator-based decoding for high-performance use cases.
- **Allocation Pooling**: Use `sync.Pool` for `Packet` structs to reach absolute zero-allocation.
- **Enhanced Testing**: Comprehensive test suite including "golden data" verification.

## Installation
```bash
go get github.com/sergle/radius/v2
```

## Quick Start (Server)
```go
package main

import (
	"log"
	"github.com/sergle/radius/v2"
)

func main() {
	handler := radius.HandlerFunc(func(ctx context.Context, request *radius.Packet) *radius.Packet {
		log.Printf("Received %s from %s", request.Code, request.ClientAddr)
		
		reply := request.Reply()
		if request.Code == radius.AccessRequest {
			if request.GetUsername() == "admin" && request.GetPassword() == "secret" {
				reply.Code = radius.AccessAccept
			} else {
				reply.Code = radius.AccessReject
			}
		}
		return reply
	})

	srv := radius.NewServer(":1812", "shared-secret", handler)
	log.Fatal(srv.ListenAndServe())
}
```

## Quick Start (Client)
```go
package main

import (
	"context"
	"log"
	"github.com/sergle/radius/v2"
)

func main() {
	client := radius.NewRadClient("127.0.0.1:1812", "shared-secret")

	req := client.NewRequest(radius.AccessRequest)
	req.AddAVP(radius.AVP{Type: radius.AttrUserName, Value: []byte("admin")})
	req.AddPassword("secret")

	// Context-aware request with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reply, err := client.SendContext(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Reply: %s", reply.Code)
}
```

## High Performance: Lazy Decoding
For high-load proxies or filters where performance is critical, use lazy decoding to avoid unnecessary allocations.

```go
// Decode without parsing attributes upfront
packet, _ := radius.DecodeRequestLazy(secret, buf)

// Attributes are parsed on-demand when using GetAVP or EachAVP
username := packet.GetUsername()

// Iterate over all attributes without heap allocations
packet.EachAVP(func(attr radius.AVP) bool {
    log.Printf("Found AVP: %d", attr.Type)
    return true
})
```

## High Performance: Zero-Allocation Pooling
For the absolute highest performance, use `sync.Pool` and direct buffer encoding.

### Pooled Decoding
```go
// Acquire a packet from the internal pool (Zero B/op)
packet, err := radius.DecodeRequestPooled(secret, buf)
if err != nil {
    log.Fatal(err)
}
defer packet.Release() // Crucial: Return packet to the pool

log.Printf("User: %s", packet.GetUsername())
```

### Direct Encoding
```go
// Encode directly into a provided buffer, avoiding allocations
buf := make([]byte, 4096)
n, err := packet.EncodeTo(buf)
```

## Migration Guide (v1 to v2)
1. **Import Path**: Change `github.com/sergle/radius` to `github.com/sergle/radius/v2`.
2. **Attribute Names**: Standard attributes are now prefixed with `Attr` (e.g., `UserName` -> `AttrUserName`).
3. **Server API**: The `Service` interface now returns `*Packet` directly. Use `HandlerFunc` for simple closures.
4. **Packet Creation**: Use `client.NewRequest(code)` or `radius.Request(code, secret)` for more control.

## Documentation
- [Go Package Documentation](https://pkg.go.dev/radius)

## References
* EAP MS-CHAPv2 packet format: http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
* EAP MS-CHAPv2: https://tools.ietf.org/html/rfc2759
* RADIUS Access-Request: https://tools.ietf.org/html/rfc2865
* RADIUS Accounting-Request: https://tools.ietf.org/html/rfc2866
* RADIUS Support For EAP: https://tools.ietf.org/html/rfc3579
* RADIUS Implementation Issues: https://tools.ietf.org/html/rfc5080

## License
MIT License. See [LICENSE](LICENSE) for details.
