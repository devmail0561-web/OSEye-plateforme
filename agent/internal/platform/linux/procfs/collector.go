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

var errStopped = fmt.Errorf("stopped")

type procEvent struct {
	EventType string `json:"event_type"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid,omitempty"`
	Name      string `json:"name,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	UID       int    `json:"uid,omitempty"`
	GID       int    `json:"gid,omitempty"`
	State     string `json:"state,omitempty"`
}

type ProcfsCollector struct {
	stopCh      chan struct{}
	mu          sync.Mutex
	running     bool
	lastErr     string
	throttle    atomic.Value // float64
	errCount    atomic.Int64
	eventsTotal atomic.Int64
}

func New() *ProcfsCollector {
	c := &ProcfsCollector{stopCh: make(chan struct{})}
	c.throttle.Store(1.0)
	return c
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

	var prevPIDs map[int]struct{}
	initialized := false

	// Reuse timers across iterations to avoid allocating a new timer per cycle.
	pauseTimer := time.NewTimer(200 * time.Millisecond)
	pauseTimer.Stop()
	scanTimer := time.NewTimer(5 * time.Second)
	scanTimer.Stop()
	defer pauseTimer.Stop()
	defer scanTimer.Stop()

	for {
		throttle, _ := c.throttle.Load().(float64)

		if throttle <= 0.0 {
			pauseTimer.Reset(200 * time.Millisecond)
			select {
			case <-ctx.Done():
				return nil
			case <-c.stopCh:
				return nil
			case <-pauseTimer.C:
			}
			continue
		}

		interval := time.Duration(float64(5*time.Second) / throttle)

		current, err := c.scan(ctx, out, prevPIDs, initialized)
		switch {
		case err == errStopped:
			return nil
		case err != nil:
			c.errCount.Add(1)
			c.mu.Lock()
			c.lastErr = err.Error()
			c.mu.Unlock()
		default:
			prevPIDs = current
			initialized = true
		}

		scanTimer.Reset(interval)
		select {
		case <-ctx.Done():
			if !scanTimer.Stop() {
				<-scanTimer.C
			}
			return nil
		case <-c.stopCh:
			if !scanTimer.Stop() {
				<-scanTimer.C
			}
			return nil
		case <-scanTimer.C:
		}
	}
}

func (c *ProcfsCollector) scan(ctx context.Context, out chan<- collector.RawEvent, prevPIDs map[int]struct{}, initialized bool) (map[int]struct{}, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("readdir /proc: %w", err)
	}

	c.mu.Lock()
	stopCh := c.stopCh
	c.mu.Unlock()

	currentPIDs := make(map[int]struct{}, len(entries))

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, errStopped
		case <-stopCh:
			return nil, errStopped
		default:
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		if !initialized {
			ev, err := readProcess(pid)
			if err != nil {
				continue
			}
			currentPIDs[pid] = struct{}{}
			ev.EventType = "process_create"
			c.emit(ctx, out, stopCh, ev)
		} else if _, seen := prevPIDs[pid]; seen {
			currentPIDs[pid] = struct{}{}
		} else {
			ev, err := readProcess(pid)
			if err != nil {
				// Process exited between ReadDir and readProcess — skip to
				// avoid an orphan process_exit on the next scan.
				continue
			}
			currentPIDs[pid] = struct{}{}
			ev.EventType = "process_create"
			c.emit(ctx, out, stopCh, ev)
		}
	}

	if initialized {
		for pid := range prevPIDs {
			if _, stillAlive := currentPIDs[pid]; !stillAlive {
				ev := &procEvent{EventType: "process_exit", PID: pid}
				c.emit(ctx, out, stopCh, ev)
			}
		}
	}

	return currentPIDs, nil
}

func (c *ProcfsCollector) emit(ctx context.Context, out chan<- collector.RawEvent, stopCh chan struct{}, ev *procEvent) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return
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
	case <-stopCh:
	}
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
	c.throttle.Store(f)
}

func (c *ProcfsCollector) Health() collector.CollectorHealth {
	c.mu.Lock()
	running, lastErr := c.running, c.lastErr
	c.mu.Unlock()
	throttle, _ := c.throttle.Load().(float64)
	return collector.CollectorHealth{
		Running:     running,
		ErrorCount:  c.errCount.Load(),
		EventsTotal: c.eventsTotal.Load(),
		ThrottlePct: throttle,
		LastError:   lastErr,
	}
}
