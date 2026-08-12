//go:build linux

package journald

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*JournaldCollector)(nil)

// JournaldCollector tails the systemd journal via `journalctl -f -o json`.
// Falls back gracefully if journald is not available.
type JournaldCollector struct {
	name       string
	units      []string // filter by systemd units (empty = all)
	priority   int      // 0=emerg..7=debug, -1=all
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount atomic.Uint64
	errorCount atomic.Uint64
	running    atomic.Bool
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

func NewJournaldCollector(units []string, priority int, logger *slog.Logger) (*JournaldCollector, error) {
	c := &JournaldCollector{
		name:     "journald",
		units:    units,
		priority: priority,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *JournaldCollector) Name() string { return c.name }

func (c *JournaldCollector) SetThrottle(factor float64) { c.throttle.Store(factor) }

func (c *JournaldCollector) Health() collector.CollectorHealth {
	lastErr, _ := c.lastError.Load().(string)
	throttlePct, _ := c.throttle.Load().(float64)
	return collector.CollectorHealth{
		Running:     c.running.Load(),
		EventsTotal: int64(c.eventCount.Load()),
		ErrorCount:  int64(c.errorCount.Load()),
		ThrottlePct: throttlePct * 100,
		LastError:   lastErr,
	}
}

// Start tails the journal via journalctl until ctx is cancelled or Stop is called.
// GO-006: if the scanner encounters a line exceeding the buffer (bufio.ErrTooLong),
// the current journalctl process is killed and a new one is spawned after a brief
// pause, so the collector never dies permanently from a single oversized log entry.
func (c *JournaldCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running.Store(true)
	defer c.running.Store(false)

	args := []string{"-f", "-o", "json", "--no-pager"}
	if c.priority >= 0 {
		args = append(args, "-p", itoa(c.priority))
	}
	for _, unit := range c.units {
		args = append(args, "-u", unit)
	}

	for {
		// Check for shutdown before (re)launching journalctl.
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		cmd := exec.CommandContext(ctx, "journalctl", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			c.lastError.Store(err.Error())
			return err
		}
		if err := cmd.Start(); err != nil {
			c.lastError.Store(err.Error())
			return err
		}

		// restartNeeded is set to true by the scanner goroutine on ErrTooLong.
		// Synchronisation: the goroutine closes done after setting restartNeeded,
		// and the outer select waits on done before reading it — no data race.
		restartNeeded := false
		done := make(chan struct{})
		go func() {
			defer close(done)
			const scanBufSize = 4 * 1024 * 1024 // 4 MB — handles large journal entries
			scanner := bufio.NewScanner(stdout)
			scanner.Buffer(make([]byte, scanBufSize), scanBufSize)
			for scanner.Scan() {
				select {
				case <-c.stopCh:
					return
				case <-ctx.Done():
					return
				default:
				}

				throttle, _ := c.throttle.Load().(float64)
				if throttle <= 0 {
					continue
				}

				line := scanner.Bytes()
				event, err := c.parseJournalLine(line)
				if err != nil {
					c.errorCount.Add(1)
					continue
				}

				select {
				case out <- event:
					c.eventCount.Add(1)
				case <-ctx.Done():
					return
				}
			}
			if err := scanner.Err(); err != nil {
				if err == bufio.ErrTooLong {
					c.logger.Warn("journald: line too long, skipping and continuing",
						slog.String("err", err.Error()))
					c.errorCount.Add(1)
					restartNeeded = true // signal outer loop to respawn journalctl
				} else {
					c.lastError.Store(err.Error())
					c.errorCount.Add(1)
				}
			}
		}()

		select {
		case <-ctx.Done():
		case <-c.stopCh:
		case <-done:
		}

		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
		<-done             // wait for goroutine to finish writing to out

		if !restartNeeded {
			return nil
		}
		// ErrTooLong — restart journalctl after a brief pause to avoid a tight loop.
		c.logger.Warn("journald: restarting after oversized line")
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *JournaldCollector) Stop() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

func (c *JournaldCollector) parseJournalLine(line []byte) (collector.RawEvent, error) {
	var entry map[string]interface{}
	if err := json.Unmarshal(line, &entry); err != nil {
		return collector.RawEvent{}, err
	}

	payload := map[string]interface{}{
		"source":       "journald",
		"timestamp_ns": time.Now().UnixNano(),
		"message":      strVal(entry, "MESSAGE"),
		"unit":         strVal(entry, "_SYSTEMD_UNIT"),
		"priority":     strVal(entry, "PRIORITY"),
		"hostname":     strVal(entry, "_HOSTNAME"),
		"pid":          strVal(entry, "_PID"),
		"comm":         strVal(entry, "_COMM"),
		"identifier":   strVal(entry, "SYSLOG_IDENTIFIER"),
	}

	raw, _ := json.Marshal(payload)
	return collector.RawEvent{
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       raw,
	}, nil
}

func strVal(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		// journald may encode binary fields (e.g. MESSAGE) as raw bytes
		return string(s)
	case []interface{}:
		// journald encodes binary MESSAGE as JSON array of byte values
		b := make([]byte, 0, len(s))
		for _, n := range s {
			if f, ok := n.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
