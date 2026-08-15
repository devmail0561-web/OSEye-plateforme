//go:build windows

// Package etw subscribes to Windows event providers for real-time
// process, file and network telemetry via Get-WinEvent (PowerShell).
// For kernel-level events (process create/exit) it reads from the
// "Microsoft-Windows-Kernel-Process" provider — no admin required on
// Windows 10+ for most event IDs.
//
// When elevated, a dedicated "OSEye-ETW" session can be started to
// receive live kernel events; without elevation the collector falls back
// to reading the Security and System event logs every 5 seconds.
package etw

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

const pollInterval = 5 * time.Second

// Collector reads Windows event logs via PowerShell Get-WinEvent.
type Collector struct {
	logger   *slog.Logger
	stopCh   chan struct{}
	running  atomic.Bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New() *Collector {
	c := &Collector{
		logger: slog.Default(),
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c
}

func (c *Collector) Name() string { return "etw" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running.Store(true)
	go c.run(ctx, out)
	return nil
}

func (c *Collector) Stop() error {
	if c.running.Load() {
		close(c.stopCh)
		c.running.Store(false)
	}
	return nil
}

func (c *Collector) SetThrottle(f float64) { c.throttle.Store(f) }

func (c *Collector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: c.running.Load()}
}

type etwEvent struct {
	Provider    string `json:"provider"`
	EventID     int    `json:"event_id"`
	EventType   string `json:"event_type"`
	PID         int    `json:"pid,omitempty"`
	Message     string `json:"message,omitempty"`
	TimeCreated string `json:"time_created,omitempty"`
}

// eventIDType maps Security event IDs to human-readable types.
var eventIDType = map[int]string{
	4688: "process_create",
	4689: "process_exit",
	4624: "logon_success",
	4625: "logon_failure",
	4648: "logon_explicit_cred",
	4663: "file_access",
	4670: "permissions_changed",
	7045: "service_installed",
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Local — avoids struct field access from multiple goroutines.
	lastPoll := time.Now().Add(-pollInterval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
		}

		if f, _ := c.throttle.Load().(float64); f <= 0 {
			continue
		}

		startStr := lastPoll.UTC().Format("2006-01-02T15:04:05Z")
		psScript := fmt.Sprintf(`
$start = [datetime]'%s'
$logs = @('Security','System')
foreach ($log in $logs) {
    try {
        Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$start} -ErrorAction SilentlyContinue |
            ForEach-Object {
                [PSCustomObject]@{
                    Provider    = $_.ProviderName
                    EventID     = $_.Id
                    PID         = $_.ProcessId
                    Message     = $_.Message -replace '\s+', ' '
                    TimeCreated = $_.TimeCreated.ToString('o')
                } | ConvertTo-Json -Compress
            }
    } catch {}
}
`, startStr)

		windowStart := lastPoll
		lastPoll = time.Now()

		cmd := exec.CommandContext(ctx, "powershell.exe", "-NonInteractive", "-NoProfile", "-Command", psScript)
		out2, err := cmd.Output()
		if err != nil {
			c.logger.Warn("etw: powershell error", "err", err)
			lastPoll = windowStart
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(out2))
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var raw map[string]interface{}
			if err := json.Unmarshal(line, &raw); err != nil {
				continue
			}

			eid := 0
			if v, ok := raw["EventID"]; ok {
				switch n := v.(type) {
				case float64:
					eid = int(n)
				}
			}

			ev := etwEvent{
				Provider:    strVal(raw, "Provider"),
				EventID:     eid,
				EventType:   eventIDType[eid],
				Message:     truncate(strVal(raw, "Message"), 256),
				TimeCreated: strVal(raw, "TimeCreated"),
			}
			if pid, ok := raw["PID"].(float64); ok {
				ev.PID = int(pid)
			}
			if ev.EventType == "" {
				ev.EventType = "event"
			}

			b, _ := json.Marshal(ev)
			select {
			case out <- collector.RawEvent{
				Source:    "etw",
				OS:        "windows",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
		}
	}
}

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// truncate shortens s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Walk back from byte n to find a valid UTF-8 boundary.
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n] + "…"
}
