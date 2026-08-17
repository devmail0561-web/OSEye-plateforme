package mapper

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

// EventMapper translates a collector.RawEvent into a fully-populated
// UniversalEventPB protobuf message.
type EventMapper struct {
	hostname string
	agentID  []byte
}

// New returns an EventMapper ready for use.
// hostname typically comes from os.Hostname(); agentID is the raw 16-byte UUID.
func New(hostname string, agentID []byte) *EventMapper {
	return &EventMapper{hostname: hostname, agentID: agentID}
}

// Map parses raw.Raw as JSON and builds a complete UniversalEventPB.
// It returns an error only when the raw payload is not valid JSON.
func (m *EventMapper) Map(raw collector.RawEvent, hashChain []byte) (*gen.UniversalEventPB, error) {
	payload := map[string]interface{}{}
	if len(raw.Raw) > 0 {
		if err := json.Unmarshal(raw.Raw, &payload); err != nil {
			return nil, fmt.Errorf("mapper: invalid json from %q: %w", raw.Source, err)
		}
	}

	id := uuid.New()
	category := m.mapCategory(raw.Source)
	if raw.Source == "ebpf" {
		if evType, _ := payload["event_type"].(string); evType == "connect" {
			category = "network"
		}
	}
	ev := &gen.UniversalEventPB{
		EventId:     id[:],
		TimestampNs: raw.Timestamp,
		Hostname:    m.hostname,
		AgentId:     m.agentID,
		Os:          raw.OS,
		Collector:   raw.Source,
		HashChain:   hashChain,
		Category:    category,
	}

	m.mapFields(payload, raw.Source, ev)
	if ev.Severity == "" {
		ev.Severity = "info"
	}
	ev.ExtraJson = raw.Raw

	return ev, nil
}

// mapCategory maps a collector source name to a UniversalEvent category.
// Covers Linux, Windows, and macOS source names.
func (m *EventMapper) mapCategory(source string) string {
	switch source {
	// Linux
	case "procfs", "ebpf":
		return "process"
	case "fanotify", "inotify":
		return "file"
	case "netlink":
		return "network"
	case "journald", "syslog":
		return "log"
	case "udev":
		return "device"
	case "auditd":
		return "audit"
	// Windows
	case "wmi", "toolhelp32":
		return "process"
	case "etw":
		return "process"
	case "fswatch":
		return "file"
	case "registry":
		return "audit"
	case "eventlog":
		return "log"
	case "winnetstat":
		return "network"
	// macOS
	case "ps":
		return "process"
	case "kqueue":
		return "file"
	case "unifiedlog":
		return "log"
	case "darwinnet":
		return "network"
	case "es":
		return "audit"
	default:
		return "unknown"
	}
}

// mapFields populates collector-specific fields on ev.
func (m *EventMapper) mapFields(payload map[string]interface{}, source string, ev *gen.UniversalEventPB) {
	switch source {
	case "procfs":
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.Uid = intField(payload, "uid")
		ev.Gid = intField(payload, "gid")
		ev.ProcessName = strField(payload, "name")
		ev.Executable = strField(payload, "exe")
		ev.Cmdline = strField(payload, "cmdline")
	case "ebpf":
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.Uid = intField(payload, "uid")
		ev.Gid = intField(payload, "gid")
		ev.ProcessName = firstStrField(payload, "comm", "name")
		ev.Executable = firstStrField(payload, "filename", "exe")
		ev.Type = strField(payload, "event_type")
		switch ev.Type {
		case "connect":
			ev.DstIp = strField(payload, "dst_ip")
			if p := intField(payload, "dst_port"); p != 0 {
				ev.DstPort = p
			}
		case "openat", "open":
			ev.Resource = strField(payload, "filename")
		}
	case "fanotify", "inotify":
		ev.Resource = firstField(payload, "path", "full_path")
		ev.Type = strField(payload, "event_type")
		ev.Pid = intField(payload, "pid")
	case "netlink":
		// Split "ip:port" strings into separate proto fields (C3 fix).
		srcIP, srcPort := splitAddr(strField(payload, "local_addr"))
		dstIP, dstPort := splitAddr(strField(payload, "remote_addr"))
		ev.SrcIp = srcIP
		ev.SrcPort = srcPort
		ev.DstIp = dstIP
		ev.DstPort = dstPort
		ev.Protocol = strField(payload, "proto")
		ev.Type = strField(payload, "event")
	case "journald", "syslog":
		ev.Resource = firstField(payload, "unit", "program")
		ev.Severity = mapLogSeverity(firstField(payload, "priority", "severity"))
		// Fallback to "identifier" when "comm" is absent (journald services without a PID).
		ev.ProcessName = firstField(payload, "comm", "identifier")
		ev.Pid = intField(payload, "pid")
	case "udev":
		ev.Resource = strField(payload, "devpath")
		ev.Type = strField(payload, "action")
	case "auditd":
		ev.Type = strField(payload, "type")
		ev.ProcessName = strField(payload, "comm")
		ev.Executable = strField(payload, "exe")
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.Uid = intField(payload, "uid")
		ev.Gid = intField(payload, "gid")

	// ── Windows ───────────────────────────────────────────────────────────────

	case "toolhelp32":
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.ProcessName = strField(payload, "name")
		ev.Type = "snapshot"

	case "etw":
		ev.Pid = intField(payload, "pid")
		ev.Type = firstField(payload, "event_type", "EventType")
		ev.ProcessName = strField(payload, "provider")
		ev.Severity = mapLogSeverityETW(intField(payload, "event_id"))

	case "registry":
		ev.Resource = strField(payload, "key_path")
		ev.Type = strField(payload, "event_type")

	case "eventlog":
		ev.Type = strField(payload, "event_type")
		ev.Severity = mapLogSeverityWin(strField(payload, "event_type"))

	case "fswatch":
		ev.Resource = strField(payload, "path") + `\` + strField(payload, "name")
		ev.Type = strField(payload, "event_type")

	case "winnetstat":
		srcIP, srcPort := splitAddr(strField(payload, "local_addr"))
		dstIP, dstPort := splitAddr(strField(payload, "remote_addr"))
		ev.SrcIp = srcIP
		ev.SrcPort = srcPort
		ev.DstIp = dstIP
		ev.DstPort = dstPort
		ev.Protocol = strField(payload, "proto")
		ev.Type = strField(payload, "state")
		ev.Pid = intField(payload, "pid")

	// ── macOS ─────────────────────────────────────────────────────────────────

	case "ps":
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.Uid = intField(payload, "uid")
		ev.ProcessName = strField(payload, "name")
		ev.Type = "snapshot"

	case "kqueue":
		ev.Resource = strField(payload, "path")
		ev.Type = strField(payload, "event_type")

	case "unifiedlog":
		ev.ProcessName = strField(payload, "process")
		ev.Pid = intField(payload, "pid")
		ev.Severity = mapLogSeverity(strField(payload, "level"))
		ev.Type = "log"

	case "darwinnet":
		srcIP, srcPort := splitAddr(strField(payload, "local_addr"))
		dstIP, dstPort := splitAddr(strField(payload, "remote_addr"))
		ev.SrcIp = srcIP
		ev.SrcPort = srcPort
		ev.DstIp = dstIP
		ev.DstPort = dstPort
		ev.Protocol = strField(payload, "proto")
		ev.Type = strField(payload, "state")

	case "es":
		ev.Type = strField(payload, "event_type")
	}
}

// mapLogSeverityETW converts a Windows Security Event ID to a severity level.
func mapLogSeverityETW(eid int32) string {
	switch int(eid) {
	case 4625, 4648, 4719: // logon failure, explicit creds, audit policy change
		return "high"
	case 4688, 4689: // process create/exit
		return "info"
	case 7045: // service installed
		return "medium"
	default:
		return "info"
	}
}

// mapLogSeverityWin maps Windows Event Log event types to severity levels.
func mapLogSeverityWin(t string) string {
	switch t {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "audit_failure":
		return "high"
	case "audit_success", "information":
		return "info"
	default:
		return "info"
	}
}

// mapLogSeverity normalizes a journald/syslog numeric priority or severity
// name into the UniversalEvent severity vocabulary (info|low|medium|high|critical).
func mapLogSeverity(v string) string {
	switch v {
	// H7 fix: add "emergency" alongside "emerg"
	case "0", "1", "2", "emerg", "emergency", "alert", "crit", "critical":
		return "critical"
	case "3", "err", "error":
		return "high"
	case "4", "warning", "warn":
		return "medium"
	default:
		return "info"
	}
}

// splitAddr splits an "ip:port" or "[ipv6]:port" string into (ip, port).
// Returns ("", 0) on empty or unparseable input.
func splitAddr(addr string) (string, int32) {
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present — return the addr as IP with port 0.
		return addr, 0
	}
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return host, 0
	}
	return host, int32(port)
}

// strField returns m[key] as a string, or "" when absent or not a string.
func strField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// firstField returns the first non-empty string field among the given keys.
func firstField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s := strField(m, k); s != "" {
			return s
		}
	}
	return ""
}

// firstStrField returns the first non-empty string value among the given keys.
func firstStrField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// intField returns m[key] as an int32, or 0 when absent or non-numeric.
// Handles float64 (JSON default), int variants, and string-encoded integers
// (journald emits _PID as a JSON string). H5/H6 fix: bounds check + string case.
func intField(m map[string]interface{}, key string) int32 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		if n > math.MaxInt32 || n < math.MinInt32 {
			return 0
		}
		return int32(n)
	case string:
		// journald emits numeric fields as JSON strings (e.g. "_PID": "1234")
		if parsed, err := strconv.ParseInt(strings.TrimSpace(n), 10, 32); err == nil {
			return int32(parsed)
		}
		return 0
	case int:
		return int32(n)
	case int32:
		return n
	case int64:
		if n > math.MaxInt32 || n < math.MinInt32 {
			return 0
		}
		return int32(n)
	default:
		return 0
	}
}
