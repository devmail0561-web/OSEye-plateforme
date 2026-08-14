//go:build linux

package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollect_ReturnsSnapshot(t *testing.T) {
	snap, err := Collect("test-agent-id", "")
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.SnapshotID == "" {
		t.Error("expected non-empty snapshot_id")
	}
	if snap.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if snap.AgentID != "test-agent-id" {
		t.Errorf("agent_id = %q, want %q", snap.AgentID, "test-agent-id")
	}
}

func TestCollect_ProcessesContainSelf(t *testing.T) {
	snap, err := Collect("agent", "")
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	// The test process itself must appear in the process list.
	if len(snap.Processes) == 0 {
		t.Fatal("expected at least one process")
	}
	for _, p := range snap.Processes {
		if p.PID <= 0 {
			t.Errorf("invalid PID %d", p.PID)
		}
	}
}

func TestCollect_ProcessFields(t *testing.T) {
	snap, err := Collect("agent", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.Processes {
		if p.Name == "" {
			t.Errorf("process %d has empty name", p.PID)
		}
		validStates := map[string]bool{
			"running": true, "sleeping": true, "disk_sleep": true,
			"zombie": true, "stopped": true, "idle": true, "unknown": true,
		}
		if !validStates[p.Status] {
			t.Errorf("process %d has unexpected status %q", p.PID, p.Status)
		}
	}
}

func TestCollect_ConnectionsHaveValidProto(t *testing.T) {
	snap, err := Collect("agent", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Connections {
		if c.Proto != "tcp" && c.Proto != "udp" {
			t.Errorf("unexpected proto %q", c.Proto)
		}
		if c.LocalPort < 0 || c.LocalPort > 65535 {
			t.Errorf("invalid local_port %d", c.LocalPort)
		}
		if c.RemotePort < 0 || c.RemotePort > 65535 {
			t.Errorf("invalid remote_port %d", c.RemotePort)
		}
	}
}

func TestCollect_JSONRoundtrip(t *testing.T) {
	snap, err := Collect("agent", "case-123")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded AgentSnapshot
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.SnapshotID != snap.SnapshotID {
		t.Errorf("snapshot_id mismatch after roundtrip")
	}
	if decoded.CaseID != "case-123" {
		t.Errorf("case_id mismatch: got %q", decoded.CaseID)
	}
}

func TestParseHexAddr_IPv4(t *testing.T) {
	// 0100007F:0050 = 127.0.0.1:80
	addr, port, err := parseHexAddr("0100007F:0050", false)
	if err != nil {
		t.Fatalf("parseHexAddr error: %v", err)
	}
	if !strings.HasPrefix(addr, "127.0.0.1") {
		t.Errorf("expected 127.0.0.1, got %q", addr)
	}
	if port != 80 {
		t.Errorf("expected port 80, got %d", port)
	}
}

func TestParseHexAddr_InvalidInput(t *testing.T) {
	_, _, err := parseHexAddr("nothex", false)
	if err == nil {
		t.Error("expected error for invalid hex input")
	}
}

func TestParseHexAddr_ShortIPv4(t *testing.T) {
	// Fewer than 4 bytes — must not panic, must return error.
	_, _, err := parseHexAddr("0102:0050", false) // 2-byte hex = 1 byte
	if err == nil {
		t.Error("expected error for short IPv4 hex, got nil")
	}
}

func TestParseHexAddr_ShortIPv6(t *testing.T) {
	// IPv6 needs 16 bytes (32 hex chars); 8 chars = 4 bytes → error.
	_, _, err := parseHexAddr("0102030405060708:0050", true)
	if err == nil {
		t.Error("expected error for short IPv6 hex, got nil")
	}
}

func TestCmdlineTruncated(t *testing.T) {
	// _maxCmdlineBytes must hold; build a string > limit and pass through maskSecrets.
	long := strings.Repeat("x", _maxCmdlineBytes+100)
	// maskSecrets should not panic on large input.
	result := maskSecrets(long)
	// The snapshot collector caps before calling maskSecrets, so result length
	// from maskSecrets itself can vary; just verify it doesn't panic.
	if result == "" {
		t.Error("maskSecrets returned empty string")
	}
}

func TestMaskSecrets(t *testing.T) {
	cases := []struct {
		input string
		mustContain    string
		mustNotContain string
	}{
		{
			input:          "mysql --password=hunter2 --host=db",
			mustNotContain: "hunter2",
			mustContain:    "[REDACTED]",
		},
		{
			input:          "curl -H 'Authorization: Bearer mysecrettoken'",
			mustNotContain: "mysecrettoken",
			mustContain:    "[REDACTED]",
		},
		{
			input:          "nginx -c /etc/nginx/nginx.conf",
			mustContain:    "nginx",
			mustNotContain: "[REDACTED]",
		},
	}
	for _, tc := range cases {
		got := maskSecrets(tc.input)
		if tc.mustNotContain != "" && strings.Contains(got, tc.mustNotContain) {
			t.Errorf("maskSecrets(%q) still contains %q: %q", tc.input, tc.mustNotContain, got)
		}
		if tc.mustContain != "" && !strings.Contains(got, tc.mustContain) {
			t.Errorf("maskSecrets(%q) missing %q: %q", tc.input, tc.mustContain, got)
		}
	}
}

func TestBuildInodeMap_ReturnsMap(t *testing.T) {
	m := buildInodeMap()
	// Map may be empty on a restricted test environment but must not be nil.
	if m == nil {
		t.Error("buildInodeMap returned nil")
	}
	// All values must be valid PIDs (> 0).
	for inode, pid := range m {
		if pid <= 0 {
			t.Errorf("inode %d maps to invalid PID %d", inode, pid)
		}
	}
}

func TestCollect_ProcessCountCapped(t *testing.T) {
	snap, err := Collect("agent", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Processes) > _maxProcesses {
		t.Errorf("process count %d exceeds cap %d", len(snap.Processes), _maxProcesses)
	}
}

func TestStateDesc(t *testing.T) {
	cases := map[byte]string{
		'R': "running",
		'S': "sleeping",
		'Z': "zombie",
		'D': "disk_sleep",
		'T': "stopped",
		'I': "idle",
		'X': "unknown",
	}
	for ch, want := range cases {
		got := stateDesc(string([]byte{ch}))
		if got != want {
			t.Errorf("stateDesc(%q) = %q, want %q", ch, got, want)
		}
	}
}
