a golang radius library (v2)
=============================

[![CI](https://github.com/sergle/radius/actions/workflows/ci.yml/badge.svg)](https://github.com/sergle/radius/actions/workflows/ci.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/sergle/radius/v2)](https://pkg.go.dev/github.com/sergle/radius/v2)
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

## Dictionaries: Loading External Vendor Dictionaries (Cisco, Microsoft, ...)
This library supports **FreeRADIUS-style** dictionary files, including `$INCLUDE`, `VENDOR`, `BEGIN-VENDOR`, vendor-specific attributes (VSAs) and `tlv` attributes (`ParseTLV`, `GetTLV`).

### Recommended: Use a “root” dictionary with `$INCLUDE`
Create a small top-level dictionary file that includes the base dictionary plus any vendor dictionaries you need.

Example `dictionary` file:

```text
$INCLUDE /path/to/freeradius/dictionary
$INCLUDE /path/to/freeradius/dictionary.cisco
$INCLUDE /path/to/freeradius/dictionary.microsoft
```

Then load it in Go:

```go
dict := radius.NewDictionary()
if err := dict.LoadFile("/path/to/your/dictionary"); err != nil {
    log.Fatal(err)
}

// Optional: make this dictionary the default for package-level lookups.
radius.SetDefaultDictionary(dict)

// Example: pre-resolve a reply template with a Cisco VSA for reuse.
replyTemplate, _ := dict.CreateRequestTemplate(radius.AccessAccept, "Reply-Message")
replyTemplate.AddVSAAttribute(dict, "Cisco", "h323-remote-address")
```

### Alternative: Load multiple files directly
You can also call `dict.LoadFile(...)` multiple times (for example, once per vendor file). Using a root dictionary with `$INCLUDE` is usually easier to manage and matches how FreeRADIUS dictionaries are commonly organized.

## Quick Start (Server)
```go
package main

import (
	"context"
	"log"
	"github.com/sergle/radius/v2"
)

func main() {
	handler := radius.HandlerFunc(func(ctx context.Context, request *radius.Packet) *radius.Packet {
		log.Printf("Received %s from %s", request.Code, request.ClientAddr)
		
		if request.Code == radius.AccessRequest {
			if request.GetUsername() == "admin" && request.GetPassword() == "secret" {
				return request.ReplyAccept()
			}
			return request.ReplyReject()
		}
		return nil
	})

	// Option A: single shared secret for all clients
	srv := radius.NewServer(":1812", "shared-secret", handler)

	// Option B: per-client shared secrets (lookup by remote host IP)
	// clients := radius.NewClientList([]radius.Client{
	// 	radius.NewClient("192.0.2.10", "secret-a"),
	// 	radius.NewClient("192.0.2.11", "secret-b"),
	// })
	// srv := radius.NewServerWithClientList(":1812", clients, handler)
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

## Quick Start (Client with CHAP)
CHAP sends a challenge and a response derived from the password:
\(response = MD5(chapID || password || challenge)\).

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/sergle/radius/v2"
)

func main() {
	client := radius.NewRadClient("127.0.0.1:1812", "shared-secret")

	req := client.NewRequest(radius.AccessRequest)
	req.AddAVP(radius.AVP{Type: radius.AttrUserName, Value: []byte("admin")})

	chapID := uint8(1)
	challenge := []byte("1234567890abcdef") // RFC 2865: 1..253 bytes
	if err := req.SetCHAPPasswordFromSecret(chapID, "secret", challenge); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reply, err := client.SendContext(ctx, req)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Reply: %s", reply.Code)
}
```

On the server, `request.VerifyCHAP(password)` checks the response; without `CHAP-Challenge` the Request Authenticator is used as the challenge.

## Tagged Attributes (RFC 2868)
Tunnel attributes (`Tunnel-Type`, `Tunnel-Medium-Type`, `Tunnel-Private-Group-ID`, ...) carry a tag (1–31) that groups attributes of the same tunnel. Dictionaries mark them with `has_tag`. Set the tag with the FreeRADIUS `Name:tag` syntax; without it the tag is 0:

```go
dict := radius.GetDefaultDictionary()
reply := request.ReplyAccept()

// Tunnel-Type:1 = VLAN, Tunnel-Medium-Type:1 = 802, Tunnel-Private-Group-ID:1 = "100"
for _, a := range [][2]string{
	{"Tunnel-Type:1", "VLAN"},
	{"Tunnel-Medium-Type:1", "802"},
	{"Tunnel-Private-Group-ID:1", "100"},
} {
	avp, err := dict.ParseAVP(a[0], a[1])
	if err != nil {
		log.Fatal(err) // unknown attribute, tag on an untagged attribute, bad value
	}
	reply.AddAVP(avp)
}

// Templates accept the same syntax
tmpl, _ := dict.CreateRequestTemplate(radius.AccessAccept, "Tunnel-Type:2", "Tunnel-Private-Group-ID:2")
tmpl.Fill(reply, "VLAN", "200")
```

Decoding strips the tag; tagged values are accepted with or without one:

```go
vlan, ok := reply.GetVLAN()                // 100, true
tt := reply.GetAVP(radius.AttrTunnelType)
log.Print(tt.Decode(reply))                // 13 (VLAN), tag removed
log.Print(dict.DecodeAVPValue(reply, *tt)) // "VLAN (tag 1)"
```

## TLV Attributes
Attributes of type `tlv` (e.g. 3GPP2, FreeRADIUS EAP-FAST) hold sub-attributes, declared with dotted ids (`59.1`) or `BEGIN-TLV` blocks. Build them with `ParseTLV`/`NewTLV` or `AddTLV` (use keyed `TLVValue` fields) and read them with `GetTLV`/`GetTLVString`; `DecodeAVPValue` renders them:

```go
avp, err := dict.ParseTLV("3GPP2", "3GPP2-Remote-IP-Address",
	radius.TLVValue{Name: "3GPP2-Remote-IP-Address-Value", Value: "10.1.2.3"},
	radius.TLVValue{Name: "3GPP2-Remote-IP-Qualifier", Value: "1"},
)
req.AddAVP(avp)

q, ok := dict.GetTLVString(p, "3GPP2", "3GPP2-Remote-IP-Qualifier") // "1", true
```

Notes:
- Sub-attributes listed one after another go into the same nested TLV. To start a second instance of a nested TLV, pass its own name with an empty `Value`.
- Sub-attributes whose type has no handler (e.g. `abinary`) are shown as raw bytes and can't be built with `ParseTLV`.
- Encrypted sub-attributes (`encrypt=1` or `encrypt=2` in the dictionary, e.g. `WiMAX-hDHCP-DHCP-RK`) need the packet's secret and authenticator, so build them with `AddTLV`, which encrypts them and adds the attribute to the packet. `ParseTLV` refuses them, because it would send them unencrypted. For a reply, create the packet with `request.Reply()` (or `ReplyAccept()` etc.) first, otherwise `AddTLV` (like `AddTunnelPassword`) returns `ErrNoRequestAuthenticator`. Accounting, CoA and Disconnect requests hide values with an all-zero authenticator (RFC 2866, RFC 5176; as FreeRADIUS). `encrypt=2` values (like Tunnel-Password, RFC 2868) can't go in an Access-Request or Status-Server: `AddTLV` and `AddTunnelPassword` return `ErrTunnelPasswordInRequest`. A failing `AddTLV` leaves the packet unchanged. For example:

  ```go
  reply := req.ReplyAccept()
  err := dict.AddTLV(reply, "WiMAX", "WiMAX-hDHCP-Server-Parameters",
  	radius.TLVValue{Name: "WiMAX-hDHCP-DHCP-RK", Value: string(key)},
  	radius.TLVValue{Name: "WiMAX-hDHCP-DHCP-RK-Key-Id", Value: "1"},
  )
  ```

  `GetTLV`, `GetTLVString`, `DecodeAVPValue` and `Packet.String` decrypt them with the packet they are given. If the ciphertext is malformed, `GetTLV` doesn't find it and the others show the raw bytes; `DecodeAVPValue(nil, …)` shows the raw bytes too (`GetTLV` and `GetTLVString` find nothing in a nil packet). A wrong secret or authenticator isn't detected: it decrypts to garbage. Only `encrypt=1` on `string` sub-attributes and `encrypt=2` on non-TLV ones are supported. Those others, and `encrypt=3`, are loaded with a warning but can't be built (`ErrUnsupportedAttributeType`) or decrypted: they are shown as raw bytes and `GetTLV` doesn't find them (nor the sub-attributes of such an encrypted TLV).
- Not supported yet: sub-attributes of vendors with a format other than `1,1` or `1,1,c` (WiMAX).

## Extended Attributes (RFC 6929)
Attributes 241–246 hold "extended" attributes, e.g. `Frag-Status` (241.1) or the IP-Port TLVs (241.5–241.7). 245 and 246 use the "long" format: a value over 251 bytes is split over several attributes. Vendors can define attributes there too (Extended-Vendor-Specific, `BEGIN-VENDOR ... format=Extended-Vendor-Specific-N` in FreeRADIUS dictionaries).

Use them by name, as other attributes:

```go
avp, err := dict.ParseAVP("Frag-Status", "More-Data-Pending") // fits one attribute
req.AddAVP(avp)

e, err := dict.ParseExtended("FreeRADIUS", "FreeRADIUS-802.1X-EAPoL-Key-Msg", longValue) // "" for standard ones
req.AddExtended(e) // splits a long value

v, ok := dict.GetExtended(p, "", "Frag-Status") // the whole value, fragments joined
```

Templates (`CreateRequestTemplate`, `AddVSAAttribute` for vendor ones) accept extended names, `ParseTLV`/`GetTLV` work for TLVs among them, and `DecodeAVPValue`/`Packet.String` show them by name. Notes:
- The builtin dictionary declares 241–246 only; load the FreeRADIUS dictionaries for the attributes in them.
- `ParseAVP` returns one attribute, so it refuses a value too long for it; use `ParseExtended` and `AddExtended`.
- `ParseTLV` also returns one attribute, and `ParseExtended` doesn't build TLVs, so a TLV value over 251 bytes can't be built from sub-attributes yet.
- Values can't be empty (RFC 6929).
- Fragments are joined only if they follow each other; a broken chain is ignored. `DecodeAVPValue` shows each fragment separately and marks the ones after the first as `Continued`.
- The only `BEGIN-VENDOR` option is `format=` (or `parent=`) naming an Extended-Vendor-Specific attribute; anything else is a load error.

## Vendor Formats
Most vendors use the standard VSA layout: a 1-byte attribute number and a 1-byte length. Some declare another layout in the dictionary with `VENDOR ... format=T,L[,c]`, and the library follows it:
- `T`: attribute number size, 1, 2 or 4 bytes (e.g. Lucent and Starent use 2, USR uses 4).
- `L`: length field size, 0, 1 or 2 bytes.
- `c`: WiMAX continuation byte, which lets a long value span several attributes.

`ParseVSA`, templates and `ParseTLV` encode with the vendor's format, and `DecodeAVPValue` and `ToVSA` decode with it. For WiMAX, `AddVSA` splits a long value over several Vendor-Specific attributes, and `GetVSA`/`GetTLV` join it back:

```go
vsa, _ := dict.ParseVSA("WiMAX", "WiMAX-Hotline-Indicator", longValue)
req.AddVSA(vsa) // adds several attributes if the value is long

v, ok := dict.GetVSA(p, "WiMAX", "WiMAX-Hotline-Indicator") // the whole value
```

`DecodeAVPValue` (and so `Packet.String`) still shows each WiMAX fragment separately.

A `VSA` built by hand uses the standard layout unless you set `Format`, e.g. `Format: dict.VendorFormat(vendorID)`. If the format is invalid (see `VendorFormat.Valid`) or the attribute number is too big for it, `ParseVSA` and templates return `ErrInvalidVendorFormat`, and `ToAVP`/`ToAVPList` log a warning and return nothing. `ToVSA` fills in `Format` and, for WiMAX, leaves the continuation byte out of `Value`.

The only `VENDOR` option is `format=T,L[,c]`; anything else is a load error.

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

## Security: Message-Authenticator (Blast-RADIUS)
RADIUS "Response Authenticator" integrity is based on an MD5 construction that is vulnerable to modern collision attacks in certain on-path (MITM) threat models (CVE-2024-3596, see [BLAST RADIUS – Attack Details](https://www.blastradius.fail/attack-details)).

This library **generates and verifies `Message-Authenticator` (HMAC-MD5, RFC 3579)** and **includes it as the first attribute on Access-* packets it encodes**, which is the recommended mitigation.

**Client:** `RadClient` rejects Access-* replies without `Message-Authenticator` (`radius.ErrMessageAuthenticatorMissing`). For legacy servers that don't send one:

```go
client.SetRequireMessageAuthenticator(false)
```

**Server:** set these before `Listen`/`Serve`:

```go
srv.SetLimitProxyState(true)              // default: drop Access-Requests with Proxy-State but no Message-Authenticator
srv.SetRequireMessageAuthenticator(false) // default: set true to drop every Access-Request without one
```

**Decoding directly:** `Message-Authenticator` is optional by default for compatibility; opt in to reject Access-* packets that omit it:

```go
packet, err := radius.DecodeRequestWithOptions(secret, buf, &radius.DecodeOptions{
	RequireMessageAuthenticator: true,
})
if err != nil {
	// err == radius.ErrMessageAuthenticatorMissing when absent on Access-*
	log.Fatal(err)
}
_ = packet
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

## Logging
The library is silent by default. Diagnostics (skipped dictionary entries, dropped server packets, ...) go to an optional `log/slog` logger:

```go
radius.SetLogger(slog.Default())
```

## Migration Guide (v1 to v2)
1. **Import Path**: Change `github.com/sergle/radius` to `github.com/sergle/radius/v2`.
2. **Attribute Names**: Standard attributes are now prefixed with `Attr` (e.g., `UserName` -> `AttrUserName`).
3. **Server API**: The `Service` interface now returns `*Packet` directly. Use `HandlerFunc` for simple closures.
4. **Packet Creation**: Use `client.NewRequest(code)` or `radius.Request(code, secret)` for more control.

## Documentation
- [Go Package Documentation](https://pkg.go.dev/github.com/sergle/radius/v2)

## References
* EAP MS-CHAPv2 packet format: http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
* EAP MS-CHAPv2: https://tools.ietf.org/html/rfc2759
* RADIUS Access-Request: https://tools.ietf.org/html/rfc2865
* RADIUS Accounting-Request: https://tools.ietf.org/html/rfc2866
* RADIUS Support For EAP: https://tools.ietf.org/html/rfc3579
* RADIUS Implementation Issues: https://tools.ietf.org/html/rfc5080

## License
MIT License. See [LICENSE](LICENSE) for details.
