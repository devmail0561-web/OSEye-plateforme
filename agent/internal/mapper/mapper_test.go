package mapper

import (
	"encoding/json"
	"testing"

	"github.com/oseye/agent/internal/collector"
)

func rawEvent(source string, payload map[string]interface{}) collector.RawEvent {
	raw, _ := json.Marshal(payload)
	return collector.RawEvent{
		Source:    source,
		OS:        "linux",
		Timestamp: 1_700_000_000_000_000_000,
		Raw:       raw,
	}
}

func TestMapCategory(t *testing.T) {
	m := New("host", []byte("agent"))
	cases := map[string]string{
		"procfs":     "process",
		"ebpf":       "process",
		"fanotify":   "file",
		"inotify":    "file",
		"netlink":    "network",
		"journald":   "log",
		"syslog":     "log",
		"udev":       "device",
		"auditd":     "audit",
		"unknown_xx": "unknown",
	}
	for src, want := range cases {
		if got := m.mapCategory(src); got != want {
			t.Errorf("mapCategory(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestMapCommonFields(t *testing.T) {
	m := New("myhost", []byte("agent-id-bytes"))
	ev, err := m.Map(rawEvent("procfs", map[string]interface{}{}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if string(ev.Hostname) != "myhost" {
		t.Errorf("Hostname = %q, want myhost", ev.Hostname)
	}
	if string(ev.AgentId) != "agent-id-bytes" {
		t.Errorf("AgentId mismatch")
	}
	if len(ev.EventId) != 16 {
		t.Errorf("EventId len = %d, want 16 (UUID v4 binary)", len(ev.EventId))
	}
	if ev.TimestampNs != 1_700_000_000_000_000_000 {
		t.Errorf("TimestampNs = %d", ev.TimestampNs)
	}
	if ev.Os != "linux" || ev.Collector != "procfs" {
		t.Errorf("Os/Collector mismatch")
	}
	if string(ev.HashChain) != "chain" {
		t.Errorf("HashChain mismatch")
	}
}

func TestMapProcfsFields(t *testing.T) {
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("procfs", map[string]interface{}{
		"pid": 100, "ppid": 1, "name": "bash", "exe": "/bin/bash",
		"cmdline": "-c ls", "uid": 1000, "gid": 1000,
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.Pid != 100 || ev.Ppid != 1 || ev.Uid != 1000 || ev.Gid != 1000 {
		t.Errorf("bad numeric fields: %+v", ev)
	}
	if ev.ProcessName != "bash" || ev.Executable != "/bin/bash" || ev.Cmdline != "-c ls" {
		t.Errorf("bad string fields: %+v", ev)
	}
	if ev.Category != "process" || ev.Collector != "procfs" {
		t.Errorf("bad category/collector: %+v", ev)
	}
}

func TestMapFanotifyFields(t *testing.T) {
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("fanotify", map[string]interface{}{
		"path": "/etc/passwd", "event_type": "open", "pid": 42,
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.Resource != "/etc/passwd" || ev.Type != "open" || ev.Pid != 42 {
		t.Errorf("bad fanotify fields: %+v", ev)
	}
	if ev.Category != "file" {
		t.Errorf("bad category: %v", ev.Category)
	}
}

func TestMapNetlinkFields(t *testing.T) {
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("netlink", map[string]interface{}{
		"local_addr": "10.0.0.1:1234", "remote_addr": "8.8.8.8:53",
		"proto": "tcp", "event": "new",
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.SrcIp != "10.0.0.1:1234" || ev.DstIp != "8.8.8.8:53" {
		t.Errorf("bad net ips: %+v", ev)
	}
	if ev.Protocol != "tcp" || ev.Type != "new" {
		t.Errorf("bad net fields: %+v", ev)
	}
	if ev.Category != "network" {
		t.Errorf("bad category: %v", ev.Category)
	}
}

func TestMapLogSeverityMapping(t *testing.T) {
	cases := map[string]string{
		"0": "critical", "1": "critical", "2": "critical",
		"3": "high", "error": "high",
		"4": "medium", "warning": "medium",
		"5": "info", "7": "info", "": "info", "bogus": "info",
	}
	for in, want := range cases {
		if got := mapLogSeverity(in); got != want {
			t.Errorf("mapLogSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapInvalidJSON(t *testing.T) {
	m := New("host", []byte("agent"))
	_, err := m.Map(collector.RawEvent{
		Source: "procfs", OS: "linux", Raw: []byte("not json"),
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMapExtraJsonPreserved(t *testing.T) {
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("procfs", map[string]interface{}{"pid": 5}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if len(ev.ExtraJson) == 0 {
		t.Fatal("ExtraJson should not be empty")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(ev.ExtraJson, &parsed); err != nil {
		t.Fatalf("ExtraJson not valid JSON: %v", err)
	}
	if got := int(parsed["pid"].(float64)); got != 5 {
		t.Errorf("ExtraJson pid = %d, want 5", got)
	}
}
