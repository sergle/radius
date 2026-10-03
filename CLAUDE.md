# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`github.com/sergle/radius/v2` — a RADIUS client/server/codec library in Go (single package `radius` at the repo root; forked from bronze1man/radius). No external dependencies. Runnable examples live in `examples/{client,chap_client,server}`.

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

**Dictionary drives AVP typing.** `AVP` is just `{Type, Value []byte}`. Decoding/stringifying a value (`AVP.Decode`, `AVP.String`, `AttributeType.String`) looks up the attribute's name and type string in the package-level *default dictionary* (`GetDefaultDictionary`/`SetDefaultDictionary`, guarded by `defaultDictionaryMu`), then maps the type string to an `avpDataType` handler via `attrTypeHandlers` in `dictionary.go` (`integer`→`avp_uint32.go`, `password`→`avp_password.go`, `vsa`→`avp_vendor.go`, etc.). Unknown types fall back to `avpBinary`.

- In production the default dictionary starts **empty**; users must load one (`LoadFile` for FreeRADIUS-style files with `$INCLUDE`/`VENDOR`/`BEGIN-VENDOR`, or `LoadBuiltin`).
- `init_test.go` loads the builtin dictionary into the default dictionary for all tests — tests implicitly depend on it.
- `dictionary.builtin` is embedded via `go:embed`.

**Adding a standard attribute** touches two places that must stay in sync: the `Attr*` constant in `AttributeType.go` and the `ATTRIBUTE`/`VALUE` lines in `dictionary.builtin`. Attributes with well-known enum values may also get a typed `*Enum` with `String()` in `avp.go` and a `Get*` helper on `Packet` in `packet.go`. Recent commits (RFC 5176, 5090, 3580) are good examples of the pattern.

**Packet encode/decode (`packet.go`).**
- `EncodeTo` automatically adds and computes `Message-Authenticator` (HMAC-MD5) on all Access-* packets, generates a random Request Authenticator for Access-Request, and zeroes it for other request types before computing the MD5 authenticator (RFC 2866/5176).
- Three decode flavors, each with `...WithOptions` variants taking `DecodeOptions` (e.g. `RequireMessageAuthenticator`): normal (`DecodeRequest/Reply`), pooled (`...Pooled`, from `packetPool`; caller must `Release()`), and lazy (`...Lazy`, keeps `RawAVPs` unparsed; `GetAVP`/`EachAVP`/`HasAVP` iterate raw bytes). Accessors must handle both `AVPs` and `RawAVPs`.
- Replies are verified against the request authenticator (`DecodeReply(secret, buf, requestAuth)`).

**Server (`server.go`).** `ListenAndServe` = `Listen` (binds; then `Addr()` is valid, e.g. for `:0`) + `Serve`; `Stop` is safe before `Listen` and repeatable. Tests use `startTestServer`. UDP loop with pooled buffers; each datagram is handled in a goroutine. The secret is resolved per remote IP via `ClientList` (`client.go`) or the single shared secret. The request is decoded with `DecodeRequestPooled` and **released after the handler returns**, and the reply is encoded into a separate pooled buffer — handlers must not retain the request `*Packet` beyond the call. `Identifier` and `Secret` are copied onto the returned reply automatically.

**Client (`radclient.go`).** `RadClient.SendContext` sends over UDP and decodes the reply with the request's authenticator. `NewRequest`/`NewAccessRequest`/etc. pre-fill the secret.

**Templates (`template.go`).** `RequestTemplate` pre-resolves attribute/VSA names against a dictionary once, then `Fill`/`CreateRequest` adds values positionally. Includes a special VLAN template (RFC 3580 tunnel attributes).

**Auth helpers:** CHAP (`chap.go`), MS-CHAPv2 (`msChapv2.go`), EAP packets (`eap.go`, `avp_eap_message.go`), RFC 5090 Digest (`digest.go`, `digest_helpers.go`).

## Notes

- VSAs assume 1-byte vendor attribute type and length (see TODOs in `avp_vendor.go`); WiMAX/Lucent-style formats are not supported.
- CI is GitHub Actions (`.github/workflows/ci.yml`): gofmt check, `go vet`, `make build`, `go test`, `go test -race`, and `make fuzz`.