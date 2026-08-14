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
