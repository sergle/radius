package radius

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// typesTestDict declares one attribute of each type.
const typesTestDict = `
ATTRIBUTE	T-Ifid		201	ifid
ATTRIBUTE	T-Ether		202	ether
ATTRIBUTE	T-Date		203	date
ATTRIBUTE	T-Combo		204	combo-ip
`

func TestAvpTypesDecode(t *testing.T) {
	d := loadTLVDict(t, typesTestDict)
	tests := []struct {
		name  string
		typ   AttributeType
		value []byte
		want  string
	}{
		{"ifid", 201, []byte{0, 0x11, 0x22, 0x33, 0x0a, 0xbc, 0, 0}, "11:2233:abc:0"},
		{"ether", 202, []byte{0, 0x11, 0x22, 0xaa, 0xbb, 0xcc}, "00:11:22:aa:bb:cc"},
		{"date", 203, []byte{0x5f, 0x5e, 0x10, 0}, "2020-09-13T12:26:40Z"},
		{"combo IPv4", 204, []byte{192, 0, 2, 1}, "192.0.2.1"},
		{"combo IPv6", 204, net.ParseIP("2001:db8::1"), "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.DecodeAVPValue(nil, AVP{Type: tt.typ, Value: tt.value}); got != tt.want {
				t.Errorf("DecodeAVPValue = %q, want %q", got, tt.want)
			}
		})
	}

	if got := avpIfid.Value(nil, AVP{Value: tests[0].value}); !bytes.Equal(got.([]byte), tests[0].value) {
		t.Errorf("ifid Value = %v", got)
	}
	if got := avpEther.Value(nil, AVP{Value: tests[1].value}); got.(net.HardwareAddr).String() != tests[1].want {
		t.Errorf("ether Value = %v", got)
	}
	if got := avpDate.Value(nil, AVP{Value: tests[2].value}); !got.(time.Time).Equal(time.Unix(1600000000, 0)) {
		t.Errorf("date Value = %v", got)
	}
	if got := avpComboIP.Value(nil, AVP{Value: tests[3].value}); !got.(net.IP).Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("combo-ip Value = %v", got)
	}
}

// Values of the wrong length are shown as raw bytes.
func TestAvpTypesMalformed(t *testing.T) {
	d := loadTLVDict(t, typesTestDict)
	tests := []struct {
		name    string
		handler avpDataType
		typ     AttributeType
		value   []byte
	}{
		{"ifid short", avpIfid, 201, []byte{1, 2, 3}},
		{"ether long", avpEther, 202, []byte{1, 2, 3, 4, 5, 6, 7}},
		{"date short", avpDate, 203, []byte{1, 2}},
		{"combo 5 bytes", avpComboIP, 204, []byte{1, 2, 3, 4, 5}},
		{"empty", avpComboIP, 204, []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := AVP{Type: tt.typ, Value: tt.value}
			raw := avpBinary.String(nil, a)
			if got := tt.handler.String(nil, a); got != raw {
				t.Errorf("String = %q, want %q", got, raw)
			}
			if got := d.DecodeAVPValue(nil, a); got != raw {
				t.Errorf("DecodeAVPValue = %q, want %q", got, raw)
			}
			tt.handler.Value(nil, a) // no panic
		})
	}
}

func TestAvpTypesParse(t *testing.T) {
	d := loadTLVDict(t, typesTestDict)
	tests := []struct {
		name, attr, value string
		want              []byte
	}{
		{"ifid", "T-Ifid", "11:2233:ABC:0", []byte{0, 0x11, 0x22, 0x33, 0x0a, 0xbc, 0, 0}},
		{"ether", "T-Ether", "00:11:22:AA:BB:CC", []byte{0, 0x11, 0x22, 0xaa, 0xbb, 0xcc}},
		{"ether dashes", "T-Ether", "00-11-22-aa-bb-cc", []byte{0, 0x11, 0x22, 0xaa, 0xbb, 0xcc}},
		{"date seconds", "T-Date", "1600000000", []byte{0x5f, 0x5e, 0x10, 0}},
		{"date RFC 3339", "T-Date", "2020-09-13T14:26:40+02:00", []byte{0x5f, 0x5e, 0x10, 0}},
		{"combo IPv4", "T-Combo", "192.0.2.1", []byte{192, 0, 2, 1}},
		{"combo IPv6", "T-Combo", "2001:db8::1", net.ParseIP("2001:db8::1")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avp, err := d.ParseAVP(tt.attr, tt.value)
			if err != nil || !bytes.Equal(avp.Value, tt.want) {
				t.Errorf("ParseAVP = %v, %v, want %v", avp.Value, err, tt.want)
			}
		})
	}

	bad := []struct{ attr, value string }{
		{"T-Ifid", "11:2233:abc"},
		{"T-Ifid", "11:2233:abc:0:1"},
		{"T-Ifid", "12345:0:0:0"},
		{"T-Ifid", "::1"},
		{"T-Ifid", "g:0:0:0"},
		{"T-Ether", "00:11:22:aa:bb"},
		{"T-Ether", "00:11:22:33:44:55:66:77"},
		{"T-Ether", "garbage"},
		{"T-Date", "-1"},
		{"T-Date", "4294967296"},
		{"T-Date", "1969-12-31T23:59:59Z"},
		{"T-Date", "yesterday"},
		{"T-Combo", "garbage"},
		{"T-Combo", "fe80::1%eth0"},
	}
	for _, tt := range bad {
		if _, err := d.ParseAVP(tt.attr, tt.value); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("ParseAVP(%s, %q): err = %v, want ErrInvalidValue", tt.attr, tt.value, err)
		}
	}
}

// The builtin Framed-Interface-Id is an ifid.
func TestFramedInterfaceIdBuiltin(t *testing.T) {
	avp, err := GetDefaultDictionary().ParseAVP("Framed-Interface-Id", "0:0:0:1")
	if err != nil || !bytes.Equal(avp.Value, []byte{0, 0, 0, 0, 0, 0, 0, 1}) {
		t.Fatalf("ParseAVP = %v, %v", avp.Value, err)
	}
	if got := avp.String(); got != "AVP type: Framed-Interface-Id 0:0:0:1" {
		t.Errorf("AVP.String = %q", got)
	}
}

// The builtin Event-Timestamp is a date (RFC 2869 §5.28).
func TestEventTimestampBuiltin(t *testing.T) {
	avp, err := GetDefaultDictionary().ParseAVP("Event-Timestamp", "1600000000")
	if err != nil {
		t.Fatal(err)
	}
	if got := avp.String(); got != "AVP type: Event-Timestamp 2020-09-13T12:26:40Z" {
		t.Errorf("AVP.String = %q", got)
	}
	if got, ok := avp.Decode(nil).(time.Time); !ok || got.Unix() != 1600000000 {
		t.Errorf("AVP.Decode = %#v", avp.Decode(nil))
	}
}
