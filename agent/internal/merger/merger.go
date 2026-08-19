// Package merger deduplicates and merges events from overlapping collectors.
//
// Two collector pairs produce redundant events for the same kernel activity:
//   - eBPF (connect) and netlink both capture outbound TCP/UDP connections.
//     eBPF has the PID; netlink has src_ip/src_port. The merger combines them.
//   - eBPF (execve/openat) and auditd both capture process and file syscalls.
//     The auditd duplicate is dropped when eBPF already captured the same event.
//
// The merger groups events by a content fingerprint within a short time window
// (default 300 ms). On flush it emits one enriched event per group.
package merger

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

const (
	// sourcePriorityHigh is assigned to eBPF — the preferred source.
	sourcePriorityHigh = 10
	// sourcePriorityLow is assigned to fallback sources (netlink, auditd).
	sourcePriorityLow = 5
)

// sourcePriority maps collector names to their priority level.
var sourcePriority = map[string]int{
	"ebpf": sourcePriorityHigh,
}

func priority(source string) int {
	if p, ok := sourcePriority[source]; ok {
		return p
	}
	return sourcePriorityLow
}

// mergeGroup holds the primary event and any enrichment extracted from secondary events.
type mergeGroup struct {
	primary        collector.RawEvent
	primaryParsed  map[string]interface{}
	deadline       time.Time
	absorbed       int // number of secondary events dropped
}

// EventMerger deduplicates and enriches events from overlapping collectors.
type EventMerger struct {
	window  time.Duration
	groups  map[string]*mergeGroup
	mu      sync.Mutex
	out     chan collector.RawEvent
}

// New creates an EventMerger with the given merge window.
// A window of 300ms works well for local kernel events.
func New(window time.Duration) *EventMerger {
	if window <= 0 {
		window = 300 * time.Millisecond
	}
	return &EventMerger{
		window: window,
		groups: make(map[string]*mergeGroup),
		out:    make(chan collector.RawEvent, 512),
	}
}

// Events returns the output channel of deduplicated/merged events.
func (m *EventMerger) Events() <-chan collector.RawEvent { return m.out }

// Run reads from in, merges overlapping events, and flushes to out.
// Blocks until ctx is cancelled or in is closed.
func (m *EventMerger) Run(ctx context.Context, in <-chan collector.RawEvent) {
	ticker := time.NewTicker(m.window / 3)
	defer ticker.Stop()
	defer m.flushAll()

	for {
		select {
		case ev, ok := <-in:
			if !ok {
				return
			}
			m.ingest(ev)
		case <-ticker.C:
			m.flushExpired()
		case <-ctx.Done():
			return
		}
	}
}

// ingest processes a single incoming event.
func (m *EventMerger) ingest(ev collector.RawEvent) {
	if ev.Raw == nil {
		m.emit(ev)
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(ev.Raw, &parsed); err != nil {
		// Unparseable — pass through immediately.
		m.emit(ev)
		return
	}

	key, role := mergeKey(ev.Source, parsed)
	if key == "" {
		// Not a mergeable event type — pass through immediately.
		m.emit(ev)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	group, exists := m.groups[key]
	if !exists {
		// First event for this key.
		m.groups[key] = &mergeGroup{
			primary:       ev,
			primaryParsed: parsed,
			deadline:      time.Now().Add(m.window),
		}
		return
	}

	// Group already exists. Decide how to handle based on role and priority.
	switch role {
	case roleNetlinkSecondary:
		// netlink contributes src_ip/src_port to an eBPF connect event.
		if group.primaryParsed != nil {
			if srcIP, srcPort := extractLocalAddr(parsed); srcIP != "" {
				group.primaryParsed["src_ip"] = srcIP
				group.primaryParsed["src_port"] = srcPort
				// Rebuild primary Raw with enriched fields.
				if enriched, err := json.Marshal(group.primaryParsed); err == nil {
					group.primary.Raw = enriched
				}
			}
		}
		group.absorbed++

	case roleAuditdSecondary:
		// auditd duplicate of an eBPF execve/openat — drop it.
		group.absorbed++

	case rolePrimary:
		if priority(group.primary.Source) < priority(ev.Source) {
			// Existing primary has lower priority (e.g. netlink stored before eBPF arrived).
			// Promote the new high-priority event and transfer any enrichments already collected.
			// Try already-extracted src_ip first, then fall back to raw local_addr (netlink).
			if srcIP, ok := group.primaryParsed["src_ip"].(string); ok && srcIP != "" {
				parsed["src_ip"] = srcIP
				if srcPort, ok := group.primaryParsed["src_port"]; ok {
					parsed["src_port"] = srcPort
				}
			} else if srcIP, srcPort := extractLocalAddr(group.primaryParsed); srcIP != "" {
				parsed["src_ip"] = srcIP
				parsed["src_port"] = srcPort
			}
			if enriched, err := json.Marshal(parsed); err == nil {
				ev.Raw = enriched
			}
			group.primary = ev
			group.primaryParsed = parsed
			group.deadline = time.Now().Add(m.window)
		} else {
			// Same or higher priority — flush existing group and start a new one.
			m.flushGroup(key, group)
			m.groups[key] = &mergeGroup{
				primary:       ev,
				primaryParsed: parsed,
				deadline:      time.Now().Add(m.window),
			}
		}

	default:
		// Two low-priority events with the same key and no high-priority primary.
		// Keep the first, drop the second.
		group.absorbed++
	}
}

// eventRole classifies the role of an event in a merge group.
type eventRole int

const (
	rolePrimary          eventRole = iota
	roleNetlinkSecondary           // netlink event that enriches an eBPF connect
	roleAuditdSecondary            // auditd event that duplicates an eBPF syscall
	rolePassthrough                // not mergeable
)

// mergeKey returns a content fingerprint and the role of this event.
// Returns ("", rolePassthrough) for events that are not merge candidates.
func mergeKey(source string, parsed map[string]interface{}) (string, eventRole) {
	switch source {
	case "ebpf":
		evType, _ := parsed["event_type"].(string)
		switch evType {
		case "connect":
			dstIP, _ := parsed["dst_ip"].(string)
			dstPort := parsePort(parsed["dst_port"])
			if dstIP == "" || dstPort == 0 {
				return "", rolePassthrough
			}
			return fingerprint("net", dstIP, strconv.Itoa(dstPort)), rolePrimary
		case "execve":
			pid := parsePID(parsed["pid"])
			filename, _ := parsed["filename"].(string)
			if pid == 0 || filename == "" {
				return "", rolePassthrough
			}
			return fingerprint("proc", strconv.Itoa(pid), filename), rolePrimary
		case "openat":
			pid := parsePID(parsed["pid"])
			filename, _ := parsed["filename"].(string)
			if pid == 0 || filename == "" {
				return "", rolePassthrough
			}
			return fingerprint("file", strconv.Itoa(pid), filename), rolePrimary
		}

	case "netlink":
		evType, _ := parsed["event"].(string)
		if evType != "new" {
			return "", rolePassthrough
		}
		remoteAddr, _ := parsed["remote_addr"].(string)
		remoteIP, remotePort := splitHostPort(remoteAddr)
		if remoteIP == "" || remotePort == 0 {
			return "", rolePassthrough
		}
		return fingerprint("net", remoteIP, strconv.Itoa(remotePort)), roleNetlinkSecondary

	case "auditd":
		syscallName, _ := parsed["syscall"].(string)
		if syscallName != "execve" && syscallName != "openat" && syscallName != "59" && syscallName != "257" {
			return "", rolePassthrough
		}
		pid := parsePID(parsed["pid"])
		exe, _ := parsed["exe"].(string)
		if exe == "" {
			exe, _ = parsed["comm"].(string)
		}
		if pid == 0 {
			return "", rolePassthrough
		}
		if syscallName == "execve" || syscallName == "59" {
			return fingerprint("proc", strconv.Itoa(pid), exe), roleAuditdSecondary
		}
		// openat (257): auditd SYSCALL records do not include the accessed filename —
		// only the binary (exe). We cannot generate a fingerprint that matches the eBPF
		// openat key (which uses the accessed filename). Pass through to avoid false dedup.
		return "", rolePassthrough
	}

	return "", rolePassthrough
}

// fingerprint returns a short hash of the given fields for use as a group key.
func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}

// flushExpired emits all groups whose deadline has passed.
func (m *EventMerger) flushExpired() {
	now := time.Now()
	m.mu.Lock()
	var toFlush []string
	for k, g := range m.groups {
		if now.After(g.deadline) {
			toFlush = append(toFlush, k)
		}
	}
	groups := make([]*mergeGroup, 0, len(toFlush))
	for _, k := range toFlush {
		groups = append(groups, m.groups[k])
		delete(m.groups, k)
	}
	m.mu.Unlock()

	for _, g := range groups {
		m.emit(g.primary)
	}
}

// flushAll emits all remaining groups and closes the output channel.
// Uses non-blocking sends so it always terminates even if the consumer has exited.
func (m *EventMerger) flushAll() {
	m.mu.Lock()
	groups := make([]*mergeGroup, 0, len(m.groups))
	for k, g := range m.groups {
		groups = append(groups, g)
		delete(m.groups, k)
	}
	m.mu.Unlock()

	for _, g := range groups {
		select {
		case m.out <- g.primary:
		default:
			slog.Warn("merger_flush_drop", "source", g.primary.Source,
				"reason", "output channel full at shutdown")
		}
	}
	close(m.out)
}

// flushGroup emits a specific group (must be called with mu held).
func (m *EventMerger) flushGroup(key string, g *mergeGroup) {
	delete(m.groups, key)
	select {
	case m.out <- g.primary:
	default:
		slog.Warn("merger_group_drop", "source", g.primary.Source,
			"reason", "output channel full during inline flush")
	}
}

// emit sends an event to the output channel without blocking.
func (m *EventMerger) emit(ev collector.RawEvent) {
	m.out <- ev
}

// extractLocalAddr parses src_ip and src_port from a netlink event's local_addr field.
func extractLocalAddr(parsed map[string]interface{}) (string, int) {
	localAddr, _ := parsed["local_addr"].(string)
	ip, port := splitHostPort(localAddr)
	return ip, port
}

// splitHostPort splits "ip:port" into components. Returns ("", 0) on failure.
func splitHostPort(addr string) (string, int) {
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0
	}
	return host, port
}

func parsePID(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(val))
		return n
	}
	return 0
}

func parsePort(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(val))
		return n
	}
	return 0
}
