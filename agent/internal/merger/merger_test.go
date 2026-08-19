package merger

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

func makeEvent(source, eventType string, fields map[string]interface{}) collector.RawEvent {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	if eventType != "" {
		fields["event_type"] = eventType
	}
	raw, _ := json.Marshal(fields)
	return collector.RawEvent{
		Source:    source,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       raw,
	}
}

func collectN(t *testing.T, ch <-chan collector.RawEvent, n int, timeout time.Duration) []collector.RawEvent {
	t.Helper()
	var results []collector.RawEvent
	deadline := time.After(timeout)
	for len(results) < n {
		select {
		case ev, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, ev)
		case <-deadline:
			return results
		}
	}
	return results
}

func runMerger(evs []collector.RawEvent, window time.Duration) []collector.RawEvent {
	in := make(chan collector.RawEvent, len(evs)+1)
	for _, ev := range evs {
		in <- ev
	}
	close(in)

	m := New(window)
	ctx := context.Background()
	m.Run(ctx, in)

	var out []collector.RawEvent
	for ev := range m.out {
		out = append(out, ev)
	}
	return out
}

// --- Tests ---

func TestPassthrough_NonMergeableEvent(t *testing.T) {
	ev := makeEvent("procfs", "", map[string]interface{}{"pid": 123, "cmd": "ls"})
	out := runMerger([]collector.RawEvent{ev}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out))
	}
}

func TestPassthrough_UnparsableRaw(t *testing.T) {
	ev := collector.RawEvent{Source: "ebpf", OS: "linux", Raw: []byte("NOT JSON")}
	out := runMerger([]collector.RawEvent{ev}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out))
	}
}

func TestEBPF_Connect_AlonePassthrough(t *testing.T) {
	ev := makeEvent("ebpf", "connect", map[string]interface{}{
		"pid": 1234, "dst_ip": "1.2.3.4", "dst_port": 443,
	})
	out := runMerger([]collector.RawEvent{ev}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out))
	}
}

func TestNetlink_DroppedWhenEBPFConnectPresent(t *testing.T) {
	ebpfEv := makeEvent("ebpf", "connect", map[string]interface{}{
		"pid": 1234, "dst_ip": "1.2.3.4", "dst_port": float64(443), "comm": "curl",
	})
	netlinkEv := makeEvent("netlink", "", map[string]interface{}{
		"event":       "new",
		"proto":       "tcp",
		"local_addr":  "192.168.1.10:55000",
		"remote_addr": "1.2.3.4:443",
	})
	out := runMerger([]collector.RawEvent{ebpfEv, netlinkEv}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged event, got %d", len(out))
	}
	if out[0].Source != "ebpf" {
		t.Errorf("expected source=ebpf, got %s", out[0].Source)
	}
}

func TestNetlink_EnrichesEBPFWithSrcIPPort(t *testing.T) {
	ebpfEv := makeEvent("ebpf", "connect", map[string]interface{}{
		"pid": float64(1234), "dst_ip": "1.2.3.4", "dst_port": float64(443), "comm": "curl",
	})
	netlinkEv := makeEvent("netlink", "", map[string]interface{}{
		"event":       "new",
		"proto":       "tcp",
		"local_addr":  "192.168.1.10:55000",
		"remote_addr": "1.2.3.4:443",
	})
	out := runMerger([]collector.RawEvent{ebpfEv, netlinkEv}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged event, got %d", len(out))
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out[0].Raw, &parsed); err != nil {
		t.Fatalf("failed to parse merged event: %v", err)
	}
	if parsed["src_ip"] != "192.168.1.10" {
		t.Errorf("expected src_ip=192.168.1.10, got %v", parsed["src_ip"])
	}
	if parsed["src_port"] != float64(55000) {
		// src_port is stored as int — accept both float64 and int representations
		srcPort, _ := parsed["src_port"]
		t.Errorf("expected src_port=55000, got %v (%T)", srcPort, srcPort)
	}
	// pid must be preserved from the eBPF event
	if parsed["pid"] != float64(1234) {
		t.Errorf("expected pid=1234, got %v", parsed["pid"])
	}
}

func TestAuditd_DroppedWhenEBPFExecvePresent(t *testing.T) {
	ebpfEv := makeEvent("ebpf", "execve", map[string]interface{}{
		"pid": float64(5678), "filename": "/usr/bin/ls", "comm": "ls",
	})
	auditdEv := makeEvent("auditd", "", map[string]interface{}{
		"syscall": "execve",
		"pid":     "5678",
		"exe":     "/usr/bin/ls",
		"comm":    "ls",
	})
	out := runMerger([]collector.RawEvent{ebpfEv, auditdEv}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 event (auditd dropped), got %d", len(out))
	}
	if out[0].Source != "ebpf" {
		t.Errorf("expected source=ebpf, got %s", out[0].Source)
	}
}

func TestAuditd_OpenatPassthrough_NoDedupPossible(t *testing.T) {
	// auditd SYSCALL records for openat do not include the accessed filename —
	// only the binary (exe). Without a matching filename, we cannot deduplicate
	// against the eBPF openat event. Both events must pass through independently.
	ebpfEv := makeEvent("ebpf", "openat", map[string]interface{}{
		"pid": float64(9999), "filename": "/etc/passwd", "comm": "cat",
	})
	auditdEv := makeEvent("auditd", "", map[string]interface{}{
		"syscall": "openat",
		"pid":     "9999",
		"exe":     "/bin/cat", // binary that opened the file, not the file itself
		"comm":    "cat",
	})
	out := runMerger([]collector.RawEvent{ebpfEv, auditdEv}, 300*time.Millisecond)
	// Both events pass through: eBPF has filename, auditd has exe — different keys.
	if len(out) != 2 {
		t.Fatalf("expected 2 independent events (no dedup possible for openat), got %d", len(out))
	}
}

func TestNetlink_ArrivesBeforeEBPF_EBPFPromoted(t *testing.T) {
	// When netlink arrives before eBPF, eBPF must be promoted as primary and
	// the final event must contain both pid (from eBPF) and src_ip (from netlink).
	netlinkEv := makeEvent("netlink", "", map[string]interface{}{
		"event":       "new",
		"proto":       "tcp",
		"local_addr":  "10.0.0.5:44000",
		"remote_addr": "1.2.3.4:443",
	})
	ebpfEv := makeEvent("ebpf", "connect", map[string]interface{}{
		"pid": float64(7777), "dst_ip": "1.2.3.4", "dst_port": float64(443), "comm": "wget",
	})
	out := runMerger([]collector.RawEvent{netlinkEv, ebpfEv}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected 1 merged event, got %d", len(out))
	}
	if out[0].Source != "ebpf" {
		t.Errorf("expected promoted source=ebpf, got %s", out[0].Source)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out[0].Raw, &parsed); err != nil {
		t.Fatalf("failed to parse merged event: %v", err)
	}
	if parsed["pid"] != float64(7777) {
		t.Errorf("expected pid=7777 from eBPF, got %v", parsed["pid"])
	}
	if parsed["src_ip"] != "10.0.0.5" {
		t.Errorf("expected src_ip=10.0.0.5 from netlink, got %v", parsed["src_ip"])
	}
}

func TestNetlink_Passthrough_NoMatchingEBPF(t *testing.T) {
	// Netlink event with no matching eBPF — should pass through after window.
	netlinkEv := makeEvent("netlink", "", map[string]interface{}{
		"event":       "new",
		"proto":       "tcp",
		"local_addr":  "10.0.0.1:60000",
		"remote_addr": "8.8.8.8:53",
	})
	out := runMerger([]collector.RawEvent{netlinkEv}, 300*time.Millisecond)
	if len(out) != 1 {
		t.Fatalf("expected netlink passthrough, got %d events", len(out))
	}
	if out[0].Source != "netlink" {
		t.Errorf("expected source=netlink, got %s", out[0].Source)
	}
}

func TestMultipleIndependentEvents_AllPassThrough(t *testing.T) {
	evs := []collector.RawEvent{
		makeEvent("ebpf", "connect", map[string]interface{}{
			"pid": float64(1), "dst_ip": "1.1.1.1", "dst_port": float64(80),
		}),
		makeEvent("ebpf", "connect", map[string]interface{}{
			"pid": float64(2), "dst_ip": "2.2.2.2", "dst_port": float64(443),
		}),
		makeEvent("procfs", "", map[string]interface{}{"pid": float64(3)}),
	}
	out := runMerger(evs, 300*time.Millisecond)
	if len(out) != 3 {
		t.Fatalf("expected 3 independent events, got %d", len(out))
	}
}

func TestMergerWindow_EventsFlushAfterDeadline(t *testing.T) {
	in := make(chan collector.RawEvent, 2)
	ev := makeEvent("ebpf", "connect", map[string]interface{}{
		"pid": float64(42), "dst_ip": "3.3.3.3", "dst_port": float64(8080),
	})
	in <- ev

	m := New(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx, in)

	// Wait for window to expire (ticker fires at window/3 = ~17ms)
	time.Sleep(200 * time.Millisecond)
	cancel()

	var results []collector.RawEvent
	for e := range m.Events() {
		results = append(results, e)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 flushed event, got %d", len(results))
	}
}
