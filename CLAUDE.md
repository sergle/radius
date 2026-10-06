# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`github.com/sergle/radius/v2` — a RADIUS client/server/codec library in Go (single package `radius` at the repo root; forked from bronze1man/radius). No external dependencies. Runnable examples live in `examples/{client,chap_client,server,eap}`; `examples/dictload` loads dictionaries (e.g. a FreeRADIUS install, not kept in the repo) and reports warnings/errors.

## Commands

```bash
make build          # go build ./... plus the three example binaries
make test           # go test -v ./...
make bench          # benchmarks only (-run=^$)
make fuzz           # runs each Fuzz* target for FUZZTIME (default 10s); e.g. make fuzz FUZZTIME=1m

go test -run TestName -v .                 # single test
go test -bench=BenchmarkName -run=^$ .     # single benchmark
go test -fuzz=^FuzzDecodeRequest$ -fuzztime=30s .   # single fuzz target
```

## Architecture

**Dictionary drives AVP typing.** `AVP` is just `{Type, Value []byte}`. Decoding/stringifying a value (`AVP.Decode`, `AVP.String`, `AttributeType.String`) looks up the attribute's name and type string in the package-level *default dictionary* (`GetDefaultDictionary`/`SetDefaultDictionary`, an `atomic.Pointer`; each lookup takes one `Dictionary.mu` read lock), then maps the type string to an `avpDataType` handler via `attrTypeHandlers` in `dictionary.go` (`integer`→`avp_uint32.go`, `password`→`avp_password.go`, `vsa`→`avp_vendor.go`, etc.). Unknown types fall back to `avpBinary`.

- In production the default dictionary starts **empty**; users must load one (`LoadFile` for FreeRADIUS-style files with `$INCLUDE`/`VENDOR`/`BEGIN-VENDOR`, or `LoadBuiltin`).
- `init_test.go` loads the builtin dictionary into the default dictionary for all tests — tests implicitly depend on it.
- `dictionary.builtin` is embedded via `go:embed`.

**Adding a standard attribute** touches two places that must stay in sync: the `Attr*` constant in `AttributeType.go` and the `ATTRIBUTE`/`VALUE` lines in `dictionary.builtin`. Attributes with well-known enum values may also get a typed `*Enum` with `String()` in `avp.go` and a `Get*` helper on `Packet` in `packet.go`. Recent commits (RFC 5176, 5090, 3580) are good examples of the pattern.

**Packet encode/decode (`packet.go`).**
- `EncodeTo` automatically adds and computes `Message-Authenticator` (HMAC-MD5) on all Access-* packets, generates a random Request Authenticator for Access-Request, and zeroes it for other request types before computing the MD5 authenticator (RFC 2866/5176).
- Three decode flavors, each with `...WithOptions` variants taking `DecodeOptions` (e.g. `RequireMessageAuthenticator`): normal (`DecodeRequest/Reply`), pooled (`...Pooled`, from `packetPool`; caller must `Release()`), and lazy (`...Lazy`, keeps `RawAVPs` unparsed; `GetAVP`/`EachAVP`/`HasAVP` iterate raw bytes). Accessors must handle both `AVPs` and `RawAVPs`.
- Replies are verified against the request authenticator (`DecodeReply(secret, buf, requestAuth)`).

**Server (`server.go`).** `ListenAndServe` = `Listen` (binds; then `Addr()` is valid, e.g. for `:0`) + `Serve`; `Stop` is safe before `Listen` and repeatable, waits for in-flight handlers, and makes `Serve` return `ErrServerStopped`. Tests use `startTestServer`. UDP loop with pooled buffers; each datagram is handled in a goroutine (bounded by `SetMaxConcurrent`, default `DefaultMaxConcurrent`) with a per-request context derived from the server context. The secret is resolved per remote IP via `ClientList` (`client.go`) or the single shared secret. The request is decoded with `DecodeRequestPooled` and **released after the handler returns**, and the reply is encoded into a separate pooled buffer — handlers must not retain the request `*Packet` beyond the call. `Identifier`, `Secret` and the request `Authenticator` are copied onto the returned reply automatically; encrypted reply attributes (e.g. Tunnel-Password) are encrypted when added, so handlers adding them must use `request.Reply()`.

**Client (`radclient.go`).** `RadClient.SendContext` sends over UDP and decodes the reply with the request's authenticator. `NewRequest`/`NewAccessRequest`/etc. pre-fill the secret.

**Templates (`template.go`).** `RequestTemplate` pre-resolves attribute/VSA names against a dictionary once, then `Fill`/`CreateRequest` adds values positionally. Includes a special VLAN template (RFC 3580 tunnel attributes).

**Auth helpers:** CHAP (`chap.go`), MS-CHAPv2 (`msChapv2.go`), EAP packets (`eap.go`, `avp_eap_message.go`), RFC 5090 Digest (`digest.go`, `digest_helpers.go`).

## Notes

### Attribute names and numbers

- A name is unique per vendor, across top-level attributes and TLV children. Redeclaring it with another number, type or parent is a load error; an equivalent redeclaration is fine and keeps the first definition.
- Types are compared after folding in `encrypt=`/`has_tag`, and types with the same wire format count as equal (`wireTypes`: `date`≈`integer`, `eapmessage`/`ifid`/`ipv6prefix`≈`octets`). This lets builtin and FreeRADIUS definitions be loaded together.
- A number may have several names (aliases, as in FreeRADIUS). Each name encodes with its own type; the last declared or redeclared name is used for decoding. All `tlv` aliases of a number share one set of children.

### TLVs (`tlv.go`)

- `tlv` attributes and their children form a `tlvAttr` tree in `Dictionary.tlvAttrs` (vendor 0 = standard). Children are declared with dotted ids (`59.1`) or inside `BEGIN-TLV` blocks and are not top-level attributes.
- `DecodeAVPValue` renders TLVs, `ParseTLV` builds them, `GetTLV`/`GetTLVString` read them; templates treat `tlv` values as raw octets.
- A duplicate child number keeps the first child (Warn). Children ignore `has_tag`; children with `encrypt=` load, but `ParseTLV` refuses them.
- `BEGIN-TLV` blocks must close in the same file and can't contain `$INCLUDE` or vendor changes.
- Children are skipped for `extended`/`long-extended`/`evs` attributes and for vendors whose format isn't `1,1` or `1,1,c`.

### Vendor formats (`avp_vendor.go`)

- `VENDOR ... format=T,L[,c]` sets the vendor's VSA header: type of 1/2/4 bytes, length of 0/1/2 bytes, and `c` for the WiMAX continuation byte. Non-`1,1` formats are kept in `Dictionary.vendorFormat`. Any VENDOR option other than a valid `format=` is a load error.
- `VSA.Format` (zero = `1,1`) controls encoding in `ToAVP`/`ToAVPList`. `ParseVSA`, templates and `ParseTLV` fill it from the dictionary; `ToVSA` decodes with the default dictionary's format.
- An invalid format, or an attribute number too wide for its type size, is an error in `ParseVSA` and templates; `ToAVP`/`ToAVPList` log a warning and return nothing.
- `AddVSA` splits long WiMAX values over several AVPs and `GetVSA`/`GetTLV` (`eachVSA`) join them; `DecodeAVPValue` shows each fragment on its own.

### CI

- GitHub Actions (`.github/workflows/ci.yml`): gofmt check, `go vet`, `make build`, `go test`, `go test -race`, and `make fuzz`.
