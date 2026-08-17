//go:build linux

package auditd

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

// ── parseLine ────────────────────────────────────────────────────────────────

func TestParseLine_Syscall(t *testing.T) {
	c := New()
	line := `type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=5570a1b2c3d0 a1=5570a1b2c3e0 a2=5570a1b2c3f0 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/bin/bash" subj=unconfined key="exec_monitor"`

	ev, ok := c.parseLine(line)
	if !ok {
		t.Fatal("parseLine returned false for valid SYSCALL line")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(ev.Raw, &payload); err != nil {
		t.Fatalf("Raw is not valid JSON: %v", err)
	}

	if payload["type"] != "SYSCALL" {
		t.Errorf("type = %v, want SYSCALL", payload["type"])
	}
	if payload["syscall"] != "59" {
		t.Errorf("syscall = %v, want 59", payload["syscall"])
	}
	if int(payload["pid"].(float64)) != 5678 {
		t.Errorf("pid = %v, want 5678", payload["pid"])
	}
	if int(payload["ppid"].(float64)) != 1234 {
		t.Errorf("ppid = %v, want 1234", payload["ppid"])
	}
	if payload["comm"] != "bash" {
		t.Errorf("comm = %v, want bash", payload["comm"])
	}
	if payload["exe"] != "/bin/bash" {
		t.Errorf("exe = %v, want /bin/bash", payload["exe"])
	}
	if ev.Source != "auditd" || ev.OS != "linux" {
		t.Errorf("Source=%q OS=%q", ev.Source, ev.OS)
	}
	if ev.Timestamp == 0 {
		t.Error("Timestamp should not be 0")
	}
}

func TestParseLine_HexComm(t *testing.T) {
	// comm=62617368 is hex for "bash"
	c := New()
	line := `type=SYSCALL msg=audit(1700000000.000:1): arch=c000003e syscall=59 ppid=1 pid=42 uid=0 gid=0 comm=62617368 exe="/bin/bash"`

	ev, ok := c.parseLine(line)
	if !ok {
		t.Fatal("parseLine returned false")
	}
	var payload map[string]interface{}
	json.Unmarshal(ev.Raw, &payload)
	if payload["comm"] != "bash" {
		t.Errorf("hex comm: got %q, want bash", payload["comm"])
	}
}

func TestParseLine_Empty(t *testing.T) {
	c := New()
	_, ok := c.parseLine("")
	if ok {
		t.Error("parseLine should return false for empty line")
	}
}

func TestParseLine_UnknownType(t *testing.T) {
	// PROCTITLE records must be silently skipped.
	c := New()
	line := `type=PROCTITLE msg=audit(1700000000.000:100): proctitle=2F62696E2F626173680073`
	_, ok := c.parseLine(line)
	if ok {
		t.Error("parseLine should return false for PROCTITLE type")
	}
}

func TestParseLine_PATH(t *testing.T) {
	// PATH records must also be silently skipped.
	c := New()
	line := `type=PATH msg=audit(1700000000.000:456): item=0 name="/bin/bash" inode=123 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`
	_, ok := c.parseLine(line)
	if ok {
		t.Error("parseLine should return false for PATH type")
	}
}

// ── parseTimestamp ───────────────────────────────────────────────────────────

func TestParseTimestamp(t *testing.T) {
	cases := []struct {
		input string
		want  int64
	}{
		{"audit(1700000000.123:456)", 1_700_000_000_123_000_000},
		{"audit(0.000:1)", 0},
		{"audit(1.001:2)", 1_001_000_000},
		{"bad_format", 0},
		{"audit()", 0},
	}
	for _, tc := range cases {
		got := parseTimestamp(tc.input)
		if got != tc.want {
			t.Errorf("parseTimestamp(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// ── parseKV ──────────────────────────────────────────────────────────────────

func TestParseKV_QuotedAndUnquoted(t *testing.T) {
	line := `key1=val1 key2="quoted value" key3=val3`
	m, _ := parseKV(line)
	if m["key1"] != "val1" {
		t.Errorf("key1 = %q", m["key1"])
	}
	if m["key2"] != "quoted value" {
		t.Errorf("key2 = %q", m["key2"])
	}
	if m["key3"] != "val3" {
		t.Errorf("key3 = %q", m["key3"])
	}
}

// ── decodeComm ───────────────────────────────────────────────────────────────

func TestDecodeComm(t *testing.T) {
	cases := []struct{ in, want string }{
		{"62617368", "bash"},    // hex "bash"
		{"bash", "bash"},        // plain string (not hex)
		{"736C656570", "sleep"}, // hex "sleep"
		{"", ""},                // empty
		{"python3", "python3"},  // not all hex chars
	}
	for _, tc := range cases {
		if got := decodeComm(tc.in, false); got != tc.want {
			t.Errorf("decodeComm(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── Start ────────────────────────────────────────────────────────────────────

func TestStartFileNotFound(t *testing.T) {
	c := &AuditdCollector{
		logPath: "/nonexistent/audit.log",
		stopCh:  make(chan struct{}),
	}
	c.throttle.Store(1.0)

	out := make(chan collector.RawEvent, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := c.Start(ctx, out)
	if err != nil {
		t.Errorf("Start should return nil when file not found, got %v", err)
	}
}

func TestStartFromFile(t *testing.T) {
	// Write a fake audit.log, start the collector, verify it picks up lines.
	f, err := os.CreateTemp("", "auditd-test-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	c := &AuditdCollector{
		logPath: f.Name(),
		stopCh:  make(chan struct{}),
	}
	c.throttle.Store(1.0)

	out := make(chan collector.RawEvent, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		c.Start(ctx, out) //nolint:errcheck
	}()

	// Give the goroutine time to open and seek to EOF.
	time.Sleep(50 * time.Millisecond)

	// Append a SYSCALL line after Start so it gets picked up.
	line := "type=SYSCALL msg=audit(1700000001.000:1): arch=c000003e syscall=59 ppid=1 pid=100 uid=0 gid=0 comm=\"sh\" exe=\"/bin/sh\"\n"
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-out:
		if ev.Source != "auditd" {
			t.Errorf("Source = %q, want auditd", ev.Source)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(ev.Raw, &payload); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if payload["type"] != "SYSCALL" {
			t.Errorf("type = %v", payload["type"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event from auditd collector")
	}
}

func TestStopIdempotent(t *testing.T) {
	c := New()
	if err := c.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop (idempotent): %v", err)
	}
}

func TestHealthBeforeStart(t *testing.T) {
	c := New()
	h := c.Health()
	if h.Running {
		t.Error("Health.Running should be false before Start")
	}
}
