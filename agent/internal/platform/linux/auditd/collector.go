//go:build linux

package auditd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*AuditdCollector)(nil)

// AuditdCollector tails /var/log/audit/audit.log and emits SYSCALL records
// as RawEvents without CGO. If auditd is not installed the collector exits
// gracefully and emits no events.
type AuditdCollector struct {
	logPath    string
	stopCh     chan struct{}
	running    atomic.Bool
	eventCount atomic.Int64
	errorCount atomic.Int64
	lastError  atomic.Value // stores string
	throttle   atomic.Value // stores float64
}

// New returns an AuditdCollector that reads from /var/log/audit/audit.log.
func New() *AuditdCollector {
	c := &AuditdCollector{
		logPath: "/var/log/audit/audit.log",
		stopCh:  make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c
}

func (c *AuditdCollector) Name() string { return "auditd" }

// Start tails the audit log until ctx is cancelled or Stop is called.
// Returns nil immediately if the log file does not exist (auditd not installed).
func (c *AuditdCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("auditd: log file not found — collector disabled", "path", c.logPath)
			return nil
		}
		c.storeError(err.Error())
		return nil
	}
	defer f.Close()

	// Tail from EOF so we don't replay the entire history on startup.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		c.storeError(err.Error())
		return nil
	}

	c.running.Store(true)
	defer c.running.Store(false)

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				c.errorCount.Add(1)
				c.storeError(err.Error())
			}
			// File not yet updated — wait briefly before polling again.
			select {
			case <-ctx.Done():
				return nil
			case <-c.stopCh:
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			// Re-open scanner on the same fd to continue reading new lines.
			scanner = bufio.NewScanner(f)
			continue
		}

		line := scanner.Text()
		throttle, _ := c.throttle.Load().(float64)
		if throttle <= 0 {
			continue
		}

		ev, ok := c.parseLine(line)
		if !ok {
			continue
		}
		c.eventCount.Add(1)

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		}
	}
}

// Stop signals the collector to stop. Idempotent.
func (c *AuditdCollector) Stop() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

// SetThrottle implements collector.Collector. 0.0 = paused, 1.0 = full speed.
func (c *AuditdCollector) SetThrottle(factor float64) {
	c.throttle.Store(factor)
}

// Health implements collector.Collector.
func (c *AuditdCollector) Health() collector.CollectorHealth {
	lastErr, _ := c.lastError.Load().(string)
	throttle, _ := c.throttle.Load().(float64)
	return collector.CollectorHealth{
		Running:     c.running.Load(),
		EventsTotal: c.eventCount.Load(),
		ErrorCount:  c.errorCount.Load(),
		ThrottlePct: throttle,
		LastError:   lastErr,
	}
}

// parseLine parses one line from audit.log and returns a RawEvent.
// Only SYSCALL records are emitted; other record types return ok=false.
//
// Audit log format:
//
//	type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59 ...
func (c *AuditdCollector) parseLine(line string) (collector.RawEvent, bool) {
	if line == "" {
		return collector.RawEvent{}, false
	}

	fields, quotedFields := parseKV(line)

	recType, ok := fields["type"]
	if !ok || recType != "SYSCALL" {
		return collector.RawEvent{}, false
	}

	msgVal, ok := fields["msg"]
	if !ok {
		return collector.RawEvent{}, false
	}
	tsNs := parseTimestamp(msgVal)

	// Decode hex-encoded comm (e.g. comm=62617368 → "bash") or quoted comm="bash".
	// GO-005: pass wasQuoted so that names like "dead" or "cafe" are not mis-decoded.
	comm := decodeComm(fields["comm"], quotedFields["comm"])

	payload := map[string]interface{}{
		"type":    recType,
		"syscall": fields["syscall"],
		"pid":     parseInt(fields["pid"]),
		"ppid":    parseInt(fields["ppid"]),
		"uid":     parseInt(fields["uid"]),
		"gid":     parseInt(fields["gid"]),
		"exe":     stripQuotes(fields["exe"]),
		"comm":    comm,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		c.errorCount.Add(1)
		return collector.RawEvent{}, false
	}

	ts := tsNs
	if ts == 0 {
		ts = time.Now().UnixNano()
	}

	return collector.RawEvent{
		Source:    "auditd",
		OS:        "linux",
		Timestamp: ts,
		Raw:       raw,
	}, true
}

// parseTimestamp extracts nanoseconds from msg=audit(seconds.millis:serial).
func parseTimestamp(msg string) int64 {
	// msg looks like: audit(1234567890.123:456)
	start := strings.Index(msg, "(")
	end := strings.Index(msg, ")")
	if start < 0 || end <= start {
		return 0
	}
	inner := msg[start+1 : end] // "1234567890.123:456"

	dotIdx := strings.Index(inner, ".")
	if dotIdx < 0 {
		return 0
	}
	secStr := inner[:dotIdx]
	rest := inner[dotIdx+1:]

	colonIdx := strings.Index(rest, ":")
	msStr := rest
	if colonIdx >= 0 {
		msStr = rest[:colonIdx]
	}

	sec, err1 := strconv.ParseInt(secStr, 10, 64)
	ms, err2 := strconv.ParseInt(msStr, 10, 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return sec*1_000_000_000 + ms*1_000_000
}

// parseKV parses "key=value key2=value2 ..." into a value map and a quoted-status map.
// Values may be unquoted tokens or double-quoted strings.
// GO-005: the quoted map tracks which keys had their value wrapped in double quotes —
// auditd uses quoting for printable ASCII names and hex-encoding for binary names.
func parseKV(line string) (m map[string]string, quoted map[string]bool) {
	m = make(map[string]string, 16)
	quoted = make(map[string]bool, 16)
	rest := line
	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " \t")
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := rest[:eq]
		rest = rest[eq+1:]

		var val string
		if len(rest) > 0 && rest[0] == '"' {
			// Quoted value — find closing quote.
			closeQ := strings.IndexByte(rest[1:], '"')
			if closeQ < 0 {
				val = rest[1:]
				rest = ""
			} else {
				val = rest[1 : closeQ+1]
				rest = rest[closeQ+2:]
			}
			m[key] = val
			quoted[key] = true
		} else {
			// Unquoted token — read until next space.
			sp := strings.IndexByte(rest, ' ')
			if sp < 0 {
				val = rest
				rest = ""
			} else {
				val = rest[:sp]
				rest = rest[sp+1:]
			}
			m[key] = val
		}
	}
	return m, quoted
}

// decodeComm handles both hex-encoded (62617368) and quoted ("bash") comm values.
// GO-005: wasQuoted indicates the value was wrapped in double quotes by auditd,
// meaning it is already a printable ASCII name and must not be hex-decoded.
// For unquoted values, auditd always hex-encodes the comm field, so a valid
// hex string must always be decoded — no printability check is applied.
func decodeComm(s string, wasQuoted bool) string {
	if s == "" {
		return ""
	}
	if wasQuoted {
		// auditd quoted the value → it is a printable ASCII name; do not decode.
		return s
	}
	if len(s)%2 == 0 && isHex(s) {
		decoded, err := hexDecode(s)
		if err != nil {
			return s
		}
		// An unquoted hex token from auditd is always hex-encoded; return decoded.
		return decoded
	}
	return s
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func hexDecode(s string) (string, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", err
		}
		b[i] = byte(v)
	}
	return string(b), nil
}

func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func (c *AuditdCollector) storeError(msg string) {
	c.lastError.Store(msg)
}
