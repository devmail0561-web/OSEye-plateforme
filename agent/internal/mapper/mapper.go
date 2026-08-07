//go:build linux

package mapper

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/collector"
)

// EventMapper translates a collector.RawEvent into a fully-populated
// UniversalEventPB protobuf message.
type EventMapper struct {
	hostname string
	agentID  []byte
}

// New returns an EventMapper ready for use.
// hostname typically comes from os.Hostname(); agentID is the raw binary UUID.
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
	ev := &gen.UniversalEventPB{
		EventId:     id[:],
		TimestampNs: raw.Timestamp,
		Hostname:    m.hostname,
		AgentId:     m.agentID,
		Os:          raw.OS,
		Collector:   raw.Source,
		HashChain:   hashChain,
		Category:    m.mapCategory(raw.Source),
	}

	m.mapFields(payload, raw.Source, ev)
	if ev.Severity == "" {
		ev.Severity = "info"
	}
	ev.ExtraJson = raw.Raw

	return ev, nil
}

// mapCategory maps a collector source name to a UniversalEvent category.
func (m *EventMapper) mapCategory(source string) string {
	switch source {
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
	default:
		return "unknown"
	}
}

// mapFields populates collector-specific fields on ev.
func (m *EventMapper) mapFields(payload map[string]interface{}, source string, ev *gen.UniversalEventPB) {
	switch source {
	case "procfs", "ebpf":
		ev.Pid = intField(payload, "pid")
		ev.Ppid = intField(payload, "ppid")
		ev.Uid = intField(payload, "uid")
		ev.Gid = intField(payload, "gid")
		ev.ProcessName = strField(payload, "name")
		ev.Executable = strField(payload, "exe")
		ev.Cmdline = strField(payload, "cmdline")
	case "fanotify", "inotify":
		ev.Resource = firstField(payload, "path", "full_path")
		ev.Type = strField(payload, "event_type")
		ev.Pid = intField(payload, "pid")
	case "netlink":
		ev.SrcIp = strField(payload, "local_addr")
		ev.DstIp = strField(payload, "remote_addr")
		ev.Protocol = strField(payload, "proto")
		ev.Type = strField(payload, "event")
	case "journald", "syslog":
		ev.Resource = firstField(payload, "unit", "program")
		ev.Severity = mapLogSeverity(firstField(payload, "priority", "severity"))
		ev.ProcessName = strField(payload, "comm")
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
	}
}

// mapLogSeverity normalizes a journald/syslog numeric priority or severity
// name into the UniversalEvent severity vocabulary (info|low|medium|high|critical).
func mapLogSeverity(v string) string {
	switch v {
	case "0", "1", "2", "emerg", "alert", "crit", "critical":
		return "critical"
	case "3", "err", "error":
		return "high"
	case "4", "warning", "warn":
		return "medium"
	default:
		return "info"
	}
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

// intField returns m[key] as an int32, or 0 when absent or non-numeric.
// JSON unmarshal naturally produces float64 for numbers.
func intField(m map[string]interface{}, key string) int32 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int32(n)
	case int:
		return int32(n)
	case int32:
		return n
	case int64:
		return int32(n)
	default:
		return 0
	}
}
