//go:build linux

package procfs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

type procEvent struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	State   string `json:"state"`
}

// ProcfsCollector scans /proc for active processes and emits one RawEvent per process.
type ProcfsCollector struct {
	throttle    float64
	stopCh      chan struct{}
	mu          sync.Mutex
	running     bool
	errCount    atomic.Int64
	eventsTotal atomic.Int64
	lastErr     string
}

func New() *ProcfsCollector {
	return &ProcfsCollector{throttle: 1.0, stopCh: make(chan struct{})}
}

func (c *ProcfsCollector) Name() string { return "procfs" }

func (c *ProcfsCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("procfs collector already running")
	}
	c.running = true
	c.stopCh = make(chan struct{})
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	for {
		c.mu.Lock()
		throttle := c.throttle
		c.mu.Unlock()

		if throttle <= 0.0 {
			select {
			case <-ctx.Done():
				return nil
			case <-c.stopCh:
				return nil
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}

		interval := time.Duration(float64(5*time.Second) / throttle)

		if err := c.scan(ctx, out); err != nil {
			c.errCount.Add(1)
			c.mu.Lock()
			c.lastErr = err.Error()
			c.mu.Unlock()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-time.After(interval):
		}
	}
}

func (c *ProcfsCollector) scan(ctx context.Context, out chan<- collector.RawEvent) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("readdir /proc: %w", err)
	}

	c.mu.Lock()
	stopCh := c.stopCh
	c.mu.Unlock()

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil
		case <-stopCh:
			return nil
		default:
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		ev, err := readProcess(pid)
		if err != nil {
			continue
		}

		raw, err := json.Marshal(ev)
		if err != nil {
			continue
		}

		c.eventsTotal.Add(1)
		select {
		case out <- collector.RawEvent{
			Source:    "procfs",
			OS:        "linux",
			Timestamp: time.Now().UnixNano(),
			Raw:       raw,
		}:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func readProcess(pid int) (*procEvent, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	ev := &procEvent{PID: pid}

	if err := readStatus(base, ev); err != nil {
		return nil, err
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		ev.Exe = exe
	}
	if cmdline, err := readCmdline(base); err == nil {
		ev.Cmdline = cmdline
	}
	return ev, nil
}

func readStatus(base string, ev *procEvent) error {
	f, err := os.Open(filepath.Join(base, "status"))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "Name":
			ev.Name = val
		case "State":
			if fields := strings.Fields(val); len(fields) > 0 {
				ev.State = fields[0]
			}
		case "PPid":
			if n, err := strconv.Atoi(val); err == nil {
				ev.PPID = n
			}
		case "Uid":
			if fields := strings.Fields(val); len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					ev.UID = n
				}
			}
		case "Gid":
			if fields := strings.Fields(val); len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					ev.GID = n
				}
			}
		}
	}
	return scanner.Err()
}

func readCmdline(base string) (string, error) {
	data, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " ")), nil
}

func (c *ProcfsCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		select {
		case <-c.stopCh:
		default:
			close(c.stopCh)
		}
	}
	return nil
}

func (c *ProcfsCollector) SetThrottle(f float64) {
	c.mu.Lock()
	c.throttle = f
	c.mu.Unlock()
}

func (c *ProcfsCollector) Health() collector.CollectorHealth {
	c.mu.Lock()
	running, throttle, lastErr := c.running, c.throttle, c.lastErr
	c.mu.Unlock()
	return collector.CollectorHealth{
		Running:     running,
		ErrorCount:  c.errCount.Load(),
		EventsTotal: c.eventsTotal.Load(),
		ThrottlePct: throttle,
		LastError:   lastErr,
	}
}
