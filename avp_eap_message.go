package radius

var avpEapMessage AvpEapMessage

type AvpEapMessage struct{}

func (s AvpEapMessage) Value(p *Packet, a AVP) interface{} {
	eap, err := EapDecode(a.Value)
	if err != nil {
		logger().Debug("radius: EAP-Message decode", "error", err)
		return nil
	}
	return eap

}

func (s AvpEapMessage) String(p *Packet, a AVP) string {
	eap := s.Value(p, a)
	if eap == nil {
		return "nil"
	}
	return eap.(*EapPacket).String()
}

func (s AvpEapMessage) FromString(v string) []byte {
	return []byte(v)
}
