package radius

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const leakSecret = "shared-secret-xyz"

// logOutputs returns v as JSON, through slog's JSON and text handlers, and with %#v and %v.
func logOutputs(t *testing.T, v any) map[string]string {
	t.Helper()
	out := map[string]string{}
	j, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	out["json"] = string(j)
	var jb, tb bytes.Buffer
	slog.New(slog.NewJSONHandler(&jb, nil)).Info("msg", "v", v)
	slog.New(slog.NewTextHandler(&tb, nil)).Info("msg", "v", v)
	out["slog json"], out["slog text"] = jb.String(), tb.String()
	out["%#v"] = fmt.Sprintf("%#v", v)
	return out
}

// The shared secret and passwords stay out of JSON, slog and %#v.
func TestPacketSecretNotLogged(t *testing.T) {
	p := Request(AccessRequest, leakSecret)
	p.AddAVP(AVP{Type: AttrUserName, Value: []byte("alice")})
	if err := p.AddPassword("pw-user"); err != nil {
		t.Fatal(err)
	}
	p.ClientAddr = "192.0.2.1:1812"
	for name, s := range logOutputs(t, p) {
		if strings.Contains(s, leakSecret) {
			t.Errorf("%s shows the secret: %s", name, s)
		}
		if strings.Contains(s, "pw-user") {
			t.Errorf("%s shows the password: %s", name, s)
		}
		if strings.HasPrefix(name, "slog") && !strings.Contains(s, "alice") {
			t.Errorf("%s misses User-Name: %s", name, s)
		}
	}
	if s := fmt.Sprintf("%#v", p); !strings.Contains(s, "192.0.2.1:1812") {
		t.Errorf("%%#v misses ClientAddr: %s", s)
	}
}

func TestPacketNilLogValue(t *testing.T) {
	var p *Packet
	var b bytes.Buffer
	slog.New(slog.NewTextHandler(&b, nil)).Info("msg", "v", p)
	if !strings.Contains(b.String(), "v=<nil>") {
		t.Errorf("slog of nil packet: %s", b.String())
	}
	if s := fmt.Sprintf("%#v", p); s != "(*radius.Packet)(nil)" {
		t.Errorf("%%#v of nil packet: %s", s)
	}
}

func TestDefaultClientSecretNotLogged(t *testing.T) {
	cl := NewClient("192.0.2.1", leakSecret)
	out := logOutputs(t, cl)
	out["%v"] = fmt.Sprintf("%v", cl)
	out["%+v"] = fmt.Sprintf("%+v", cl)
	for name, s := range out {
		if strings.Contains(s, leakSecret) {
			t.Errorf("%s shows the secret: %s", name, s)
		}
		if !strings.Contains(s, "192.0.2.1") {
			t.Errorf("%s misses the host: %s", name, s)
		}
	}
}
