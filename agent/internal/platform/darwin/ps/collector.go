//go:build darwin

// Package ps collects a periodic process snapshot on macOS by parsing
// the output of `ps -axo pid=,ppid=,uid=,comm=`, which is available
// without special privileges and works on all macOS versions.
package ps

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

const scanInterval = 5 * time.Second

// Collector gathers process snapshots via the ps(1) command.
type Collector struct {
	stopCh   chan struct{}
	running  atomic.Bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New() *Collector {
	c := &Collector{stopCh: make(chan struct{})}
	c.throttle.Store(1.0)
	return c
}

func (c *Collector) Name() string { return "ps" }

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

type processInfo struct {
	EventType string `json:"event_type"`
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid,omitempty"`
	UID       int    `json:"uid,omitempty"`
	Name      string `json:"name,omitempty"`
}

type psProcess struct {
	pid  int
	ppid int
	uid  int
	name string
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	prevPIDs := make(map[int]struct{})
	initialized := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			if f, _ := c.throttle.Load().(float64); f <= 0 {
				continue
			}

			procs, err := listProcesses(ctx)
			if err != nil {
				continue
			}

			currentPIDs := make(map[int]struct{}, len(procs))
			for _, p := range procs {
				currentPIDs[p.pid] = struct{}{}
			}

			var events []processInfo

			if !initialized {
				for _, p := range procs {
					events = append(events, processInfo{
						EventType: "process_create",
						PID:       p.pid, PPID: p.ppid, UID: p.uid, Name: p.name,
					})
				}
			} else {
				for _, p := range procs {
					if _, seen := prevPIDs[p.pid]; !seen {
						events = append(events, processInfo{
							EventType: "process_create",
							PID:       p.pid, PPID: p.ppid, UID: p.uid, Name: p.name,
						})
					}
				}
				for pid := range prevPIDs {
					if _, exists := currentPIDs[pid]; !exists {
						events = append(events, processInfo{EventType: "process_exit", PID: pid})
					}
				}
			}

			for _, ev := range events {
				b, _ := json.Marshal(ev)
				select {
				case out <- collector.RawEvent{
					Source:    "ps",
					OS:        "darwin",
					Timestamp: time.Now().UnixNano(),
					Raw:       b,
				}:
				default:
				}
			}

			prevPIDs = currentPIDs
			initialized = true
		}
	}
}

// listProcesses runs `ps -axo pid=,ppid=,uid=,comm=` and parses its output.
// comm may contain spaces — join fields[3:] to preserve full name.
func listProcesses(ctx context.Context) ([]psProcess, error) {
	out, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,uid=,comm=").Output()
	if err != nil {
		return nil, err
	}

	var procs []psProcess
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		uid, _ := strconv.Atoi(fields[2])
		name := strings.Join(fields[3:], " ")
		procs = append(procs, psProcess{pid: pid, ppid: ppid, uid: uid, name: name})
	}
	return procs, nil
}
