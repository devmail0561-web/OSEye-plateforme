//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/oseye/agent/internal/collector"
)

// ── Collector lifecycle ───────────────────────────────────────────────────────

func TestEBPFCollectorStopIdempotent(t *testing.T) {
	c := New()
	if err := c.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop (idempotent): %v", err)
	}
}

func TestEBPFCollectorHealthBeforeStart(t *testing.T) {
	c := New()
	h := c.Health()
	if h.Running {
		t.Error("Health.Running should be false before Start")
	}
	if h.EventsTotal != 0 {
		t.Errorf("EventsTotal = %d, want 0", h.EventsTotal)
	}
}

func TestEBPFCollectorStartDegrades(t *testing.T) {
	// On any system, Start must return nil and not panic.
	// On systems without CAP_BPF it degrades gracefully (loader returns error,
	// collector logs a warning and exits with nil).
	c := New()
	out := make(chan collector.RawEvent, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx, out) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned non-nil error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return within 2s after context cancellation")
	}
}

// ── parseExecve ──────────────────────────────────────────────────────────────

func TestParseExecve(t *testing.T) {
	raw := make([]byte, 296)
	binary.LittleEndian.PutUint64(raw[0:], 1_700_000_000_000_000_000)
	binary.LittleEndian.PutUint32(raw[8:], 1234) // Pid
	binary.LittleEndian.PutUint32(raw[12:], 1)   // Ppid
	binary.LittleEndian.PutUint32(raw[16:], 0)   // Uid
	binary.LittleEndian.PutUint32(raw[20:], 0)   // Gid
	copy(raw[24:40], []byte("bash\x00"))         // Comm
	copy(raw[40:296], []byte("/bin/bash\x00"))   // Filename

	ev, ok := parseExecve(raw)
	if !ok {
		t.Fatal("parseExecve returned false for valid payload")
	}
	if ev.Type != "execve" {
		t.Errorf("Type = %q, want execve", ev.Type)
	}
	if ev.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", ev.Pid)
	}
	if ev.Ppid != 1 {
		t.Errorf("Ppid = %d, want 1", ev.Ppid)
	}
	if ev.Comm != "bash" {
		t.Errorf("Comm = %q, want bash", ev.Comm)
	}
	if ev.Filename != "/bin/bash" {
		t.Errorf("Filename = %q, want /bin/bash", ev.Filename)
	}
}

func TestParseExecveTooShort(t *testing.T) {
	_, ok := parseExecve([]byte{1, 2, 3})
	if ok {
		t.Error("parseExecve should return false for truncated payload")
	}
}

// ── parseOpenat ──────────────────────────────────────────────────────────────

func TestParseOpenat(t *testing.T) {
	raw := make([]byte, 292)
	binary.LittleEndian.PutUint64(raw[0:], 1_700_000_000_000_000_001)
	binary.LittleEndian.PutUint32(raw[8:], 42)   // Pid
	binary.LittleEndian.PutUint32(raw[12:], 100) // Uid
	binary.LittleEndian.PutUint32(raw[16:], 0)   // Flags O_RDONLY
	copy(raw[20:36], []byte("cat\x00"))
	copy(raw[36:292], []byte("/etc/passwd\x00"))

	ev, ok := parseOpenat(raw)
	if !ok {
		t.Fatal("parseOpenat returned false")
	}
	if ev.Type != "openat" {
		t.Errorf("Type = %q", ev.Type)
	}
	if ev.Pid != 42 {
		t.Errorf("Pid = %d, want 42", ev.Pid)
	}
	if ev.Filename != "/etc/passwd" {
		t.Errorf("Filename = %q, want /etc/passwd", ev.Filename)
	}
}

// ── parseConnect ─────────────────────────────────────────────────────────────

func TestParseConnectIPv4(t *testing.T) {
	raw := make([]byte, 52)
	binary.LittleEndian.PutUint64(raw[0:], 1_700_000_000_000_000_002)
	binary.LittleEndian.PutUint32(raw[8:], 99)  // Pid
	binary.LittleEndian.PutUint32(raw[12:], 50) // Uid
	binary.LittleEndian.PutUint16(raw[16:], 2)  // family = AF_INET
	// dst_port 443 in network byte order
	raw[18] = 0x01
	raw[19] = 0xBB
	// dst_ip 8.8.8.8
	raw[20] = 8
	raw[21] = 8
	raw[22] = 8
	raw[23] = 8
	copy(raw[36:52], []byte("curl\x00"))

	ev, ok := parseConnect(raw)
	if !ok {
		t.Fatal("parseConnect returned false")
	}
	if ev.Type != "connect" {
		t.Errorf("Type = %q", ev.Type)
	}
	if ev.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want 8.8.8.8", ev.DstIP)
	}
	if ev.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", ev.DstPort)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q, want curl", ev.Comm)
	}
}

// ── MarshalEvent ─────────────────────────────────────────────────────────────

func TestMarshalEvent(t *testing.T) {
	ev := EBPFEvent{
		Type:        "execve",
		TimestampNs: 1_700_000_000_000_000_000,
		Pid:         1234,
		Comm:        "bash",
		Filename:    "/bin/bash",
	}
	raw, err := MarshalEvent(ev)
	if err != nil {
		t.Fatalf("MarshalEvent error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["event_type"] != "execve" {
		t.Errorf("event_type = %v, want execve", m["event_type"])
	}
	if int(m["pid"].(float64)) != 1234 {
		t.Errorf("pid = %v, want 1234", m["pid"])
	}
}

// ── nullTerm ─────────────────────────────────────────────────────────────────

func TestNullTerm(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{'b', 'a', 's', 'h', 0, 0, 0}, "bash"},
		{[]byte{'a', 'b', 'c'}, "abc"},
		{[]byte{0, 'x'}, ""},
		{[]byte{}, ""},
	}
	for _, tc := range cases {
		if got := nullTerm(tc.in); got != tc.want {
			t.Errorf("nullTerm(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
