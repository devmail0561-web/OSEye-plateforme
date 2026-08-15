//go:build darwin

// Package unifiedlog tails the Apple Unified Log via `log stream --style ndjson`,
// the macOS replacement for syslog (available since macOS 10.12 Sierra).
package unifiedlog

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

// Collector streams log entries from the Apple Unified Log.
type Collector struct {
	logger   *slog.Logger
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(logger *slog.Logger) (*Collector, error) {
	// Verify `log` command is available
	if _, err := exec.LookPath("log"); err != nil {
		return nil, err
	}
	c := &Collector{
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "unifiedlog" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running = true
	go c.run(ctx, out)
	return nil
}

func (c *Collector) Stop() error {
	if c.running {
		close(c.stopCh)
		c.running = false
	}
	return nil
}

func (c *Collector) SetThrottle(f float64) { c.throttle.Store(f) }

func (c *Collector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: c.running}
}

type logEntry struct {
	Timestamp   string `json:"timestamp"`
	Process     string `json:"process"`
	ProcessID   int64  `json:"processID"`
	Category    string `json:"category"`
	Subsystem   string `json:"subsystem"`
	EventType   string `json:"eventType"`
	MessageType string `json:"messageType"`
	Message     string `json:"eventMessage"`
}

type unifiedLogEvent struct {
	Process   string `json:"process"`
	PID       int64  `json:"pid"`
	Category  string `json:"category"`
	Subsystem string `json:"subsystem"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	// Subscribe to security-relevant log streams:
	// sudo, authentication, and kernel messages
	cmd := exec.CommandContext(ctx,
		"log", "stream",
		"--style", "ndjson",
		"--predicate", `process == "sudo" OR process == "sshd" OR category == "authorization" OR process == "kernel"`,
		"--level", "info",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.logger.Warn("unifiedlog: pipe error", "err", err)
		return
	}

	if err := cmd.Start(); err != nil {
		c.logger.Warn("unifiedlog: start error", "err", err)
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			if f, _ := c.throttle.Load().(float64); f <= 0 {
				continue
			}

			var entry logEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}

			ev := unifiedLogEvent{
				Process:   entry.Process,
				PID:       entry.ProcessID,
				Category:  entry.Category,
				Subsystem: entry.Subsystem,
				Level:     entry.MessageType,
				Message:   entry.Message,
			}
			b, _ := json.Marshal(ev)
			select {
			case out <- collector.RawEvent{
				Source:    "unifiedlog",
				OS:        "darwin",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-c.stopCh:
	case <-done:
	}

	cmd.Process.Kill() //nolint:errcheck
	<-done
}
