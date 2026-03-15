package radius

var avpString AvpString

type AvpString struct{}

func (s AvpString) Value(p *Packet, a AVP) interface{} {
	return string(a.Value)
}
func (s AvpString) String(p *Packet, a AVP) string {
	return string(a.Value)
}
func (s AvpString) FromString(v string) []byte {
	return []byte(v)
}
