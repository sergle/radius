// Package radius implements a minimal RADIUS client/server and attribute codec.
//
// The library supports:
// - Encoding and decoding RADIUS packets (with authenticator verification)
// - Parsing FreeRADIUS-style dictionary files for attribute typing and enums
// - Convenience helpers for common attributes (User-Name, User-Password, etc.)
// - A simple UDP client (RadClient) and UDP server (Server)
//
// Most applications will:
// - Load a dictionary and set it as the default via SetDefaultDictionary
// - Create request packets with RadClient.NewRequest (or Request)
// - Send requests with RadClient.Send / SendContext and inspect replies
package radius

