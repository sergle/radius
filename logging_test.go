package radius

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordHandler collects slog messages and signals each one on ch.
type recordHandler struct {
	mu     sync.Mutex
	msgs   []string
	levels []slog.Level
	ch     chan string
}

func newRecordHandler() *recordHandler {
	return &recordHandler{ch: make(chan string, 64)}
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" " + a.String())
		return true
	})
	msg := sb.String()
	h.mu.Lock()
	h.msgs = append(h.msgs, msg)
	h.levels = append(h.levels, r.Level)
	h.mu.Unlock()
	select {
	case h.ch <- msg:
	default:
	}
	return nil
}

func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.msgs, "\n")
}

// count returns the number of messages at level containing substr.
func (h *recordHandler) count(level slog.Level, substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for i, msg := range h.msgs {
		if h.levels[i] == level && strings.Contains(msg, substr) {
			n++
		}
	}
	return n
}

// useRecordLogger installs a recording logger for the duration of the test.
func useRecordLogger(t *testing.T) *recordHandler {
	t.Helper()
	h := newRecordHandler()
	SetLogger(slog.New(h))
	t.Cleanup(func() { SetLogger(nil) })
	return h
}

// captureOutput returns everything fn writes to stdout, stderr and the std logger.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	log.SetOutput(f)
	defer func() {
		os.Stdout, os.Stderr = stdout, stderr
		log.SetOutput(os.Stderr)
	}()

	fn()

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeNoisyDictionary writes a dictionary that triggers every informational message.
func writeNoisyDictionary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	inc := "VENDOR\tV\t42\n"
	if err := os.WriteFile(filepath.Join(dir, "dictionary.inc"), []byte(inc), 0644); err != nil {
		t.Fatal(err)
	}
	main := `
ATTRIBUTE	Bad-Id-Attr	999	string
ATTRIBUTE	Bad-Flag-Attr	200	string	encrypt=x
ATTRIBUTE	Odd-Crypt-Attr	201	string	encrypt=9
VALUE	Missing-Attr	Foo	1
$INCLUDE	dictionary.vqp
$INCLUDE	dictionary.inc
$INCLUDE	dictionary.inc
`
	path := filepath.Join(dir, "dictionary")
	if err := os.WriteFile(path, []byte(main), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFileSilentByDefault(t *testing.T) {
	path := writeNoisyDictionary(t)
	out := captureOutput(t, func() {
		if err := NewDictionary().LoadFile(path); err != nil {
			t.Fatalf("LoadFile: %v", err)
		}
	})
	if out != "" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestLoadFileLogsToInjectedLogger(t *testing.T) {
	h := useRecordLogger(t)
	path := writeNoisyDictionary(t)
	if err := NewDictionary().LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	got := h.all()
	for _, want := range []string{"Bad-Id-Attr", "Bad-Flag-Attr", "Odd-Crypt-Attr", "Missing-Attr", "dictionary.vqp", "dictionary.inc"} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q:\n%s", want, got)
		}
	}
}

func TestDictionaryErrorsCarryContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dictionary")
	if err := os.WriteFile(path, []byte("VENDOR\tV\tnotanumber\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := NewDictionary().LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "notanumber") {
		t.Fatalf("expected error mentioning vendor id, got %v", err)
	}
}

func TestEapDecodeFailSilent(t *testing.T) {
	bad := AVP{Type: AttrEAPMessage, Value: []byte{2, 0}}
	out := captureOutput(t, func() {
		_ = bad.String()
	})
	if out != "" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestNewAVPAndTemplateSilentByDefault(t *testing.T) {
	d := GetDefaultDictionary()
	out := captureOutput(t, func() {
		d.NewAVP("No-Such-Attr", "x")
		d.NewVSA("No-Such-Vendor", "x", "y")
		tmpl := &AttributeTemplate{attrType: AttrNASPort, handler: avpUint32}
		tmpl.Add(Request(AccessRequest, "s"), "not-a-number")
	})
	if out != "" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestNewAVPLogsToInjectedLogger(t *testing.T) {
	h := useRecordLogger(t)
	GetDefaultDictionary().NewAVP("No-Such-Attr", "x")
	if !strings.Contains(h.all(), "No-Such-Attr") {
		t.Fatalf("log missing attribute name:\n%s", h.all())
	}
}

func TestServerLogsToInjectedLogger(t *testing.T) {
	h := useRecordLogger(t)
	srv := NewServer("127.0.0.1:0", "secret", HandlerFunc(func(ctx context.Context, r *Packet) *Packet { return nil }))
	addr, _ := startTestServer(t, srv)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// too short to be a RADIUS packet
	if _, err := conn.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-h.ch:
		if !strings.Contains(msg, "decode") {
			t.Fatalf("unexpected log message: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no log message from server")
	}
}
