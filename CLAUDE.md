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
- `EncodeTo` automatically adds and computes `Message-Authenticator` (HMAC-MD5) on all Access-* packets (and fills one the caller added to any other code), generates a random Request Authenticator for Access-Request if unset, and zeroes it for other request types before computing the MD5 authenticator (RFC 2866/5176). It writes only the output, never `p` (safe to encode/send one packet concurrently): the sent authenticator is `b[4:20]`, which `RadClient` uses to verify the reply. Output over 4096 bytes is `ErrPacketTooLarge`, a smaller buffer that's too short `ErrBufferTooSmall`.
- Message-Authenticator is hashed with the packet's own Request Authenticator in Access-Request/Status-Server, zeros in Accounting/CoA/Disconnect requests (RFC 5176 §3.5, as FreeRADIUS), and the request's in replies.
- Decode flavors, each with `...WithOptions` variants taking `DecodeOptions` (e.g. `RequireMessageAuthenticator`; `ValidateAttributes` makes lazy decoders check attribute lengths, which the others always do, `ErrInvalidAttributeLength`): normal (`DecodeRequest/Reply`), pooled (`...Pooled`, from `packetPool`; caller must `Release()`), lazy (`...Lazy`, keeps `RawAVPs` unparsed; `GetAVP`/`EachAVP`/`HasAVP` iterate raw bytes), and both (`...LazyPooled`). Accessors and encoding see `RawAVPs` first, then `AVPs` (`AddAVP` appends there); deleting (`SetAVP`, `DeleteAVP`) parses `RawAVPs` into `AVPs` first; `DeleteAVP` matches by `Value` storage, so `GetAVP` pointers survive `AddAVP` and lazy packets.
- Replies are verified against the request authenticator (`DecodeReply(secret, buf, requestAuth)`). Request decoders refuse reply codes and reply decoders request codes (`ErrUnexpectedCode`); `RadClient` also skips replies whose code doesn't answer the request (`PacketCode.answers`).
- Encrypted attributes are hidden with `cryptAuthenticator(method)`: all zeros for Accounting/CoA/Disconnect requests and for `encrypt=2` in any request, the packet's own for `encrypt=1` in Access-Request/Status-Server, the request's for replies; `encryptAuthenticator` refuses a reply without one (`ErrNoRequestAuthenticator`) and `encrypt=2` in Access-Request/Status-Server (`ErrTunnelPasswordInRequest`, RFC 2868). A random Request Authenticator is generated before the first value is hidden (`ensureAuthenticator`), not at `Encode`. encrypt=2 salts come from `Packet.newSalt`, unique among those generated for the packet (`salts`, cleared by `Reset`, cloned by `Copy`; not scanned from received/`AddAVP`'d values); `AvpTunnelPassword.Encode` alone doesn't track them. `saveEncrypt`/`restoreEncrypt` undo the authenticator and salts when adding fails.
- `encrypt=2` with `has_tag` is `tunnel-password` (tag byte first); without it `salt-encrypted-<type>` (`avp_salt.go`, RFC 2548, e.g. MS-MPPE-Send-Key, `Alc-LI-Action integer encrypt=2`): decrypted, then decoded as the type (non-strings are encoded before encrypting). Other `encrypt=` on non-string value types (and tagged `encrypt=2`) is `octets`. `ParseVSA` returns encrypted VSAs with the plaintext and unexported `enc`/`tag`; `Packet.AddVSA` (returns an error) encrypts them (p unchanged on error), `ToAVP`/`ToAVPList` refuse them, `GetVSA` decrypts them.

**Formatting.** `Packet.String`, `AVP.StringWithPacket` and `DecodeAVPValue` decrypt encrypted values with the packet; `Packet.StringMasked`/`AVP.StringMasked(p)`/`Dictionary.DecodeAVPValueMasked` format a copy of `p` with `masked` set (`withMasked`), and the password, tunnel-password and salt handlers, `plainValue` and `tlvAttr.formatValue` then show `*****` (`maskedValue`), as do `StringWithPacket`/`DecodeAVPValue`/`rawVSAString` for credential-equivalent attributes (`masksAttr`: CHAP-Password, Digest-Response, Digest-HA1; `masksVSA`: MS-CHAP(2)-Response), and EAP-Message shows only Identity/Notification/Nak data (`EapPacket.stringMasked`). `*Packet` logs through slog as `StringMasked` (`LogValue`); `Packet.Secret`/`DefaultClient.Secret` are kept out of JSON, slog and `%#v`.

**Server (`server.go`).** `ListenAndServe` = `Listen` (binds; then `Addr()` is valid, e.g. for `:0`) + `Serve`; `Stop` is safe before `Listen` and repeatable, waits for in-flight handlers, and makes `Serve` return `ErrServerStopped`. Tests use `startTestServer`. UDP loop with pooled buffers; each datagram is handled in a goroutine (bounded by `SetMaxConcurrent`, default `DefaultMaxConcurrent`) with a per-request context derived from the server context. The secret is resolved per remote IP via `ClientList` (`client.go`) or the single shared secret. The request is decoded with `DecodeRequestLazyPooledWithOptions` (handlers read attributes via `EachAVP`/`GetAVP`, `request.AVPs` is empty) and **released after the handler returns**, and the reply is encoded into a separate pooled buffer — handlers must not retain the request `*Packet` beyond the call. `Identifier`, `Secret` and the request `Authenticator` are copied onto the returned reply automatically; encrypted reply attributes (e.g. Tunnel-Password) are encrypted when added, so handlers adding them must use `request.Reply()` (else `ErrNoRequestAuthenticator`).

**Client (`radclient.go`).** `RadClient.SendContext` sends over UDP and decodes the reply with the request's authenticator. `NewRequest`/`NewAccessRequest`/etc. pre-fill the secret.

**Templates (`template.go`).** `RequestTemplate` pre-resolves attribute/VSA names against a dictionary once, then `Fill`/`CreateRequest` adds values positionally. Includes a special VLAN template (RFC 3580 tunnel attributes).

**Auth helpers:** CHAP (`chap.go`), MS-CHAPv2 (`msChapv2.go`: NT-Response, S= authenticator response, RFC 3079 MPPE keys), EAP packets (`eap.go`, `avp_eap_message.go`), RFC 5090 Digest (`digest.go`, `digest_helpers.go`).

## Notes

### Attribute names and numbers

- A name is unique per vendor, across top-level attributes and TLV children. Redeclaring it with another number, type, parent or `encrypt=` method is a load error, for every kind (top-level, VSA, TLV child, extended, EVS); an equivalent redeclaration is fine and keeps the first definition.
- Top-level and extended types are compared after folding in `encrypt=` (and top-level `has_tag`) with `effectiveType`, and types with the same wire format count as equal (`wireTypes`: `eapmessage`≈`octets`); the `encrypt=` method is compared separately (`encryptMethod`, which counts `password` as 1 and `tunnel-password` as 2). So builtin `password` ≈ `string encrypt=1` and `tunnel-password` ≈ `string has_tag,encrypt=2`, letting builtin and FreeRADIUS definitions load together. TLV children compare type and `encrypt=` as written.
- Untagged `encrypt=2` types: `salt-encrypted-string`≈`salt-encrypted-octets` (`wireTypes`), both method 2 in `encryptMethod`. Extended attributes have no tags, so there `tunnel-password` ≈ untagged `encrypt=2` (`extWireType`).
- A number may have several names (aliases, as in FreeRADIUS). Each name encodes with its own type; the last declared or redeclared name is used for decoding. All `tlv` aliases of a number share one set of children and the first definition's `encrypt=`; an alias's own `encrypt=` is ignored with a warning.

### TLVs (`tlv.go`)

- `tlv` attributes and their children form a `tlvAttr` tree in `Dictionary.tlvAttrs` (vendor 0 = standard). Children are declared with dotted ids (`59.1`) or inside `BEGIN-TLV` blocks and are not top-level attributes.
- `DecodeAVPValue` renders TLVs, `GetTLV`/`GetTLVString` read them; templates treat `tlv` values as raw octets.
- `Dictionary.ParseTLV` returns a `*TLV` builder (`tlvTop` holds the resolved top-level attribute); `Add`/`AddTLV` (new nested instance) look names up under `d.mu` and store plain encoded values in a `tlvNode` tree, encrypted ones as plaintext. `Packet.AddTLV` encrypts into a new buffer (the builder is unchanged), splits WiMAX/long-extended values, and restores the authenticator and salts on error; `ToAVP` gives the zero AVP if anything is encrypted or it doesn't fit one AVP.
- A duplicate child number keeps the first child (Warn). Children ignore `has_tag`.
- `encrypt=1` (on `string`) and `encrypt=2` (on non-`tlv`) children are encrypted like top-level attributes but without a tag byte, by `Packet.AddTLV` using `p.encryptAuthenticator(method)`; `ToAVP` refuses them (`ErrEncryptedAttribute`). `GetTLV` returns the decrypted value; only malformed ciphertext is detected (not found), a wrong secret or authenticator gives garbage. `formatValue` decrypts with `p`, else shows octets.
- Other `encrypt=` (`encrypt=1` on non-strings, encrypted `tlv`s, `encrypt=3`) stay marked (`tlvAttr.canEncrypt` false, Warn at load): never built (`ErrUnsupportedAttributeType` from `TLV.Add`/`AddTLV`, also for children of such a TLV), never decrypted (`GetTLV` doesn't find them or their children, formatting shows octets).
- `BEGIN-TLV` blocks must close in the same file and can't contain `$INCLUDE` or vendor changes.
- Children are skipped for `evs` attributes, VSAs of an extended type, and vendors whose format isn't `1,1` or `1,1,c`. Extended attributes may be TLVs: their root `tlvAttr.outer` is 241–246.

### Vendor formats (`avp_vendor.go`)

- `VENDOR ... format=T,L[,c]` sets the vendor's VSA header: type of 1/2/4 bytes, length of 0/1/2 bytes, and `c` for the WiMAX continuation byte. Non-`1,1` formats are kept in `Dictionary.vendorFormat`. Any VENDOR option other than a valid `format=` is a load error.
- `VSA.Format` (zero = `1,1`) controls encoding in `ToAVP`/`ToAVPList`. `ParseVSA`, templates and `ParseTLV` fill it from the dictionary; `ToVSA` decodes with the default dictionary's format.
- An invalid format, or an attribute number too wide for its type size, is an error in `ParseVSA` and templates; `ToAVP`/`ToAVPList` log a warning and return nothing.
- `AddVSA` splits long WiMAX values over several AVPs and `GetVSA`/`GetTLV` (`eachVSA`) join them; `DecodeAVPValue` shows each fragment on its own; `chainStart` finds the AVP's place in the packet so later fragments are marked `Continued` and named after the first.

### Extended attributes (`extended.go`, RFC 6929)

- `241`–`246` are declared `extended`/`long-extended` (builtin has them); `241.N` declares an extended attribute, `241.N.M` a TLV child, `241.26` the `evs` placeholder. `BEGIN-VENDOR V format=<evs attribute>` (or `parent=`) declares EVS attributes of V (dotted `241.26.V.N` ids are skipped at Debug).
- Definitions are `extAttr` in `Dictionary.extAttrs` (vendor 0, or the EVS vendor) and `extNums` (decoding, last alias wins). Names are unique against top-level, VSA and TLV names of the same vendor; they aren't top-level, so `GetAttributeID`/`HasAttribute` don't see them.
- On the wire an AVP stays `{241, ext-type [flags] data}`; `ExtendedAttr` (ExtType 26 = EVS; 245/246 use the More-flag format) is built by `ParseExtended` and templates, split by `ToAVPList`/`AddExtended` (More on all but the last, EVS header in the first fragment only). `check` refuses other types, empty values and Vendor-Ids over 24 bits.
- `GetExtended`/`GetTLV` (`eachExtended`) join contiguous fragments; a chain that is interrupted, changes Extended-Type, has a short More fragment (RFC 6929 §2.2) or ends with More set is skipped. `DecodeAVPValue` shows each fragment on its own; `chainStart` finds the AVP's place in the packet so later fragments are marked `Continued` and named after the first (`Packet.String` tracks chains in one pass instead: `chainState`, on its copy's `chain`).
- `ParseAVP` accepts standard extended names when the value fits one AVP; extended attributes have no tags, and `encrypt=` (or `password`/`tunnel-password` typed) ones load but can't be built.

### CI

- GitHub Actions (`.github/workflows/ci.yml`): gofmt check, `go vet`, `make build`, `go test`, `go test -race`, and `make fuzz`.
