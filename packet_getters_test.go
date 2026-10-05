package radius

import (
	"net"
	"strings"
	"testing"
)

// getterValues is a snapshot of all Get* helpers.
type getterValues struct {
	username, password, sessionID, nasID string
	nasIP                                string
	statusType                           AcctStatusTypeEnum
	outOctets, inOctets                  uint64
	nasPort                              uint32
	nasPortType                          NASPortTypeEnum
	serviceType                          ServiceTypeEnum
}

func readGetters(p *Packet) getterValues {
	v := getterValues{
		username:    p.GetUsername(),
		password:    p.GetPassword(),
		sessionID:   p.GetAcctSessionId(),
		nasID:       p.GetNASIdentifier(),
		statusType:  p.GetAcctStatusType(),
		outOctets:   p.GetAcctTotalOutputOctets(),
		inOctets:    p.GetAcctTotalInputOctets(),
		nasPort:     p.GetNASPort(),
		nasPortType: p.GetNASPortType(),
		serviceType: p.GetServiceType(),
	}
	if ip := p.GetNasIpAddress(); ip != nil {
		v.nasIP = ip.String()
	}
	return v
}

func u32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func getterPacket() *Packet {
	p := Request(AccessRequest, "secret")
	p.AddAVP(
		AVP{Type: AttrUserName, Value: []byte("alice")},
		AVP{Type: AttrAcctSessionId, Value: []byte("sess-1")},
		AVP{Type: AttrNASIdentifier, Value: []byte("nas-1")},
		AVP{Type: AttrNASIPAddress, Value: net.IPv4(10, 0, 0, 1).To4()},
		AVP{Type: AttrAcctStatusType, Value: u32(uint32(AcctStatusTypeEnumStop))},
		AVP{Type: AttrAcctOutputOctets, Value: u32(7)},
		AVP{Type: AttrAcctOutputGigawords, Value: u32(2)},
		AVP{Type: AttrAcctInputOctets, Value: u32(9)},
		AVP{Type: AttrAcctInputGigawords, Value: u32(3)},
		AVP{Type: AttrNASPort, Value: u32(1812)},
		AVP{Type: AttrNASPortType, Value: u32(uint32(NASPortTypeEnumEthernet))},
		AVP{Type: AttrServiceType, Value: u32(uint32(ServiceTypeEnumFramed))},
	)
	p.AddPassword("s3cret")
	return p
}

var fullGetters = getterValues{
	username:    "alice",
	password:    "s3cret",
	sessionID:   "sess-1",
	nasID:       "nas-1",
	nasIP:       "10.0.0.1",
	statusType:  AcctStatusTypeEnumStop,
	outOctets:   2<<32 + 7,
	inOctets:    3<<32 + 9,
	nasPort:     1812,
	nasPortType: NASPortTypeEnumEthernet,
	serviceType: ServiceTypeEnumFramed,
}

// checkGetters runs the getters on built, decoded and lazily decoded packets.
func checkGetters(t *testing.T, p *Packet, want getterValues) {
	t.Helper()
	if got := readGetters(p); got != want {
		t.Errorf("built:\n got %+v\nwant %+v", got, want)
	}
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRequest("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := readGetters(dec); got != want {
		t.Errorf("decoded:\n got %+v\nwant %+v", got, want)
	}
	lazy, err := DecodeRequestLazy("secret", buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := readGetters(lazy); got != want {
		t.Errorf("lazy:\n got %+v\nwant %+v", got, want)
	}
}

func TestGettersBuiltinDictionary(t *testing.T) {
	checkGetters(t, getterPacket(), fullGetters)
}

func TestGettersEmptyDictionary(t *testing.T) {
	old := GetDefaultDictionary()
	defer SetDefaultDictionary(old)
	SetDefaultDictionary(NewDictionary())

	checkGetters(t, getterPacket(), fullGetters)
}

func TestGettersAbsent(t *testing.T) {
	p := Request(AccessRequest, "secret")
	p.AddAVP(AVP{Type: AttrReplyMessage, Value: []byte("x")})
	checkGetters(t, p, getterValues{})

	old := GetDefaultDictionary()
	defer SetDefaultDictionary(old)
	SetDefaultDictionary(NewDictionary())
	checkGetters(t, p, getterValues{})
}

// Raw integers of the wrong length are ignored when no dictionary is loaded.
func TestGettersEmptyDictionaryShortIntegers(t *testing.T) {
	old := GetDefaultDictionary()
	defer SetDefaultDictionary(old)
	SetDefaultDictionary(NewDictionary())

	p := Request(AccessRequest, "secret")
	for _, at := range []AttributeType{AttrAcctStatusType, AttrAcctOutputOctets, AttrAcctOutputGigawords,
		AttrAcctInputOctets, AttrAcctInputGigawords, AttrNASPort, AttrNASPortType, AttrServiceType} {
		p.AddAVP(AVP{Type: at, Value: []byte{1, 2, 3}})
	}
	checkGetters(t, p, getterValues{})
}

// Values decoded to an unexpected type yield the zero value.
func TestGettersUnexpectedTypes(t *testing.T) {
	d := NewDictionary()
	const dict = `
ATTRIBUTE	User-Name		1	integer
ATTRIBUTE	NAS-IP-Address		4	integer
ATTRIBUTE	NAS-Port		5	ipaddr
ATTRIBUTE	Service-Type		6	string
ATTRIBUTE	NAS-Identifier		32	integer
ATTRIBUTE	Acct-Status-Type	40	ipaddr
ATTRIBUTE	Acct-Input-Octets	42	string
ATTRIBUTE	Acct-Output-Octets	43	string
ATTRIBUTE	Acct-Session-Id		44	integer
ATTRIBUTE	Acct-Input-Gigawords	52	ipaddr
ATTRIBUTE	Acct-Output-Gigawords	53	ipaddr
ATTRIBUTE	NAS-Port-Type		61	string
`
	if err := d.loadReader("test", strings.NewReader(dict)); err != nil {
		t.Fatal(err)
	}
	old := GetDefaultDictionary()
	defer SetDefaultDictionary(old)
	SetDefaultDictionary(d)

	p := getterPacket()
	// password stays decryptable via the builtin handler fallback
	checkGetters(t, p, getterValues{password: "s3cret"})
}
