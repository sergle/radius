package radius

import (
	"strconv"
	"unicode"
	"unicode/utf8"
)

var avpString AvpString

type AvpString struct{}

func (s AvpString) Value(p *Packet, a AVP) any {
	return string(a.Value)
}
func (s AvpString) String(p *Packet, a AVP) string {
	return printable(string(a.Value))
}
func (s AvpString) FromString(v string) []byte {
	return []byte(v)
}

// printable returns s, or s quoted if it has non-graphic characters or starts with a quote (CWE-117).
func printable(s string) string {
	if s != "" && s[0] == '"' {
		return strconv.QuoteToGraphic(s)
	}
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsGraphic(r) {
			return strconv.QuoteToGraphic(s)
		}
	}
	return s
}
