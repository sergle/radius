# RADIUS Library for Go (v2)

A feature-rich, high-performance RADIUS (Remote Authentication Dial-In User Service) library for Go. This version (v2) is a significant refactor and enhancement of the original `bronze1man/radius` library, offering improved API clarity, comprehensive dictionary support, and a robust testing suite.

## 🚀 Key Features

- **Intuitive Go-Native API**: Simplified interfaces for building RADIUS servers and clients.
- **Full Dictionary Support**: Seamlessly parse and use FreeRADIUS-style dictionary files.
- **Built-in Attributes**: Minimal standard attributes included out-of-the-box in `dictionary.builtin`.
- **Prepared Request Templates**: Pre-resolve attributes and VSAs for efficient packet construction.
- **Security First**: Built-in support for `Message-Authenticator` (RFC 3579) and password encryption.
- **Extended Protocol Support**: Includes support for MS-CHAPv2 and EAP.
- **Lazy Packet Decoding**: Optimized-for-speed iterator-based decoding (Go 1.21+).
- **Allocation Pooling**: Built-in support for `sync.Pool` to achieve zero-allocation decoding.
- **Comprehensive Testing**: Large test suite including "golden data" verification for protocol correctness.

## 🏗 Project Architecture

The library is organized around several core components:

| Component | Responsibility |
| :--- | :--- |
| `Packet` | Repesents a RADIUS packet. Handles encoding, decoding, and authenticator verification. |
| `AVP` | Attribute-Value Pair. The basic data unit in RADIUS. |
| `Dictionary` | Parses and manages RADIUS dictionaries for attribute/value lookups. |
| `Server` | A UDP-based RADIUS server with a simple `Handler` interface. |
| `RadClient` | A client for sending RADIUS requests and receiving replies. |
| `Template` | Provides a way to pre-resolve attribute mappings for faster packet creation. |

## 📁 Project Structure

```text
.
├── AttributeType.go        # Attribute type definitions
├── PacketCode.go           # RADIUS packet code definitions (Access-Request, etc.)
├── avp.go                  # Base AVP handling and types
├── avp_*.go                # Specialized AVP type handlers (IP, uint32, Password, etc.)
├── client.go               # Client interface and list management
├── radclient.go            # Actual RADIUS client implementation
├── server.go               # RADIUS server implementation
├── dictionary.go           # Dictionary parser and manager
├── packet.go               # Core Packet struct and encoding/decoding logic
├── template.go             # Prepared request templates
├── eap.go                  # EAP protocol support
├── msChapv2.go             # MS-CHAPv2 support
├── examples/               # Client and server implementation examples
└── dictionary.builtin      # Minimal standard RADIUS dictionary
```

## 🛠 Getting Started

### Installation

```bash
go get github.com/sergle/radius/v2
```

### Simple Server Example

```go
package main

import (
	"log"
	"github.com/sergle/radius/v2"
)

func main() {
	handler := radius.HandlerFunc(func(ctx context.Context, request *radius.Packet) *radius.Packet {
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

### Advanced Usage: Using Templates

Templates allow you to pre-resolve dictionary names to IDs, which is faster and safer for production use.

```go
dict := radius.NewDictionary()
dict.LoadFile("path/to/dictionary")

// Pre-resolve "Reply-Message" attribute
template, _ := dict.GetTemplate("Reply-Message")

reply := request.Reply()
template.Add(reply, "Welcome to the system!")
```

### High-Performance: Lazy Packet Decoding
For high-performance proxies or scenarios with many attributes, use the lazy decoder to keep memory allocations at a minimum.

```go
// Fully lazy decoding - header only
packet, err := radius.DecodeRequestLazy(secret, buf)

// Attributes are walked on-demand
packet.EachAVP(func(a radius.AVP) bool {
    // Process attribute...
    return true
})
```

### High-Performance: Zero-Allocation Decoding (Pooled)
While lazy decoding is great for filters, full packets can be decoded with **zero allocations** using the built-in `sync.Pool` support.

```go
// Reuses a Packet struct from the pool
packet, err := radius.DecodeRequestPooled(secret, buf)
if err != nil {
    return err
}
defer packet.Release() // Release back to pool after use

// Full access to AVPs without any heap pressure
username := packet.GetUsername()
```

**Benefits (20-Attribute Packet)**:
- **Allocations**: 7 -> 0
- **Memory**: 2256 B -> 0 B
- **Performance**: ~10x faster than standard decoding

**Benefits (20-Attribute Packet)**:
- **Allocations**: 7 -> 1 (Struct reuse is possible)
- **Memory**: 2256 B -> 112 B
- **Performance**: ~9x faster than standard decoding

## 🧪 Development and Testing

The library uses standard Go testing tools. To run the tests:

```bash
go test -v ./...
```

To run benchmarks:

```bash
go test -bench=. ./...
```

## 📜 References

- [RFC 2865](https://tools.ietf.org/html/rfc2865) - Remote Authentication Dial In User Service (RADIUS)
- [RFC 2866](https://tools.ietf.org/html/rfc2866) - RADIUS Accounting
- [RFC 3579](https://tools.ietf.org/html/rfc3579) - RADIUS Support For EAP
- [RFC 5080](https://tools.ietf.org/html/rfc5080) - RADIUS Implementation Issues
