//go:build linux

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
	// C3 fix: SrcIp/DstIp must hold only the IP; ports go in SrcPort/DstPort.
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("netlink", map[string]interface{}{
		"local_addr": "10.0.0.1:1234", "remote_addr": "8.8.8.8:53",
		"proto": "tcp", "event": "new",
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.SrcIp != "10.0.0.1" || ev.SrcPort != 1234 {
		t.Errorf("bad src: ip=%q port=%d", ev.SrcIp, ev.SrcPort)
	}
	if ev.DstIp != "8.8.8.8" || ev.DstPort != 53 {
		t.Errorf("bad dst: ip=%q port=%d", ev.DstIp, ev.DstPort)
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

func TestMapNetlinkAddrSplit(t *testing.T) {
	// C3 fix: SrcIp/DstIp must contain only the IP, SrcPort/DstPort the port.
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("netlink", map[string]interface{}{
		"local_addr":  "10.0.0.1:1234",
		"remote_addr": "8.8.8.8:53",
		"proto":       "udp",
		"event":       "new",
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.SrcIp != "10.0.0.1" {
		t.Errorf("SrcIp = %q, want %q", ev.SrcIp, "10.0.0.1")
	}
	if ev.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234", ev.SrcPort)
	}
	if ev.DstIp != "8.8.8.8" {
		t.Errorf("DstIp = %q, want %q", ev.DstIp, "8.8.8.8")
	}
	if ev.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", ev.DstPort)
	}
}

func TestIntFieldOverflow(t *testing.T) {
	// H5 fix: values > MaxInt32 must clamp to 0, not silently overflow.
	m := map[string]interface{}{
		"big":      float64(3_000_000_000),
		"neg_big":  float64(-3_000_000_000),
		"normal":   float64(42),
		"str_pid":  "1234",
		"str_bad":  "abc",
		"null_val": nil,
	}
	if got := intField(m, "big"); got != 0 {
		t.Errorf("big overflow: got %d, want 0", got)
	}
	if got := intField(m, "neg_big"); got != 0 {
		t.Errorf("neg_big overflow: got %d, want 0", got)
	}
	if got := intField(m, "normal"); got != 42 {
		t.Errorf("normal: got %d, want 42", got)
	}
	if got := intField(m, "str_pid"); got != 1234 {
		// H6 fix: string-encoded integer (journald _PID) must be parsed.
		t.Errorf("str_pid: got %d, want 1234", got)
	}
	if got := intField(m, "str_bad"); got != 0 {
		t.Errorf("str_bad: got %d, want 0", got)
	}
	if got := intField(m, "null_val"); got != 0 {
		t.Errorf("null_val: got %d, want 0", got)
	}
}

func TestMapLogSeverityEmergency(t *testing.T) {
	// H7 fix: "emergency" must map to "critical".
	if got := mapLogSeverity("emergency"); got != "critical" {
		t.Errorf("mapLogSeverity(emergency) = %q, want critical", got)
	}
	if got := mapLogSeverity("emerg"); got != "critical" {
		t.Errorf("mapLogSeverity(emerg) = %q, want critical", got)
	}
}

func TestMapJournaldIdentifierFallback(t *testing.T) {
	// journald services without a process emit "identifier" but no "comm".
	m := New("host", []byte("agent"))
	ev, err := m.Map(rawEvent("journald", map[string]interface{}{
		"unit":       "sshd.service",
		"priority":   "5",
		"identifier": "sshd",
	}), []byte("chain"))
	if err != nil {
		t.Fatalf("Map error: %v", err)
	}
	if ev.ProcessName != "sshd" {
		t.Errorf("ProcessName = %q, want sshd", ev.ProcessName)
	}
}
