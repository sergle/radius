package radius

var avpEapMessage AvpEapMessage

type AvpEapMessage struct{}

// Value returns the decoded *EapPacket, or the raw []byte if the value is not
// a complete EAP packet (e.g. one RFC 3579 fragment; use Packet.GetEAPMessage).
func (s AvpEapMessage) Value(p *Packet, a AVP) interface{} {
	eap, err := EapDecode(a.Value)
	if err != nil {
		return a.Value
	}
	return eap
}

// String formats the EAP packet, falling back to the raw bytes.
func (s AvpEapMessage) String(p *Packet, a AVP) string {
	eap, err := EapDecode(a.Value)
	if err != nil {
		return avpBinary.String(p, a)
	}
	return eap.String()
}

func (s AvpEapMessage) FromString(v string) []byte {
	return []byte(v)
}
