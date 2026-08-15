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
	running  bool
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

type processInfo struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	UID  int    `json:"uid"`
	Name string `json:"name"`
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
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
			for _, p := range procs {
				b, _ := json.Marshal(p)
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
		}
	}
}

// listProcesses runs `ps -axo pid=,ppid=,uid=,comm=` and parses its output.
// Each column is separated by whitespace; comm may contain spaces.
func listProcesses(ctx context.Context) ([]processInfo, error) {
	out, err := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,uid=,comm=").Output()
	if err != nil {
		return nil, err
	}

	var procs []processInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// ps -o pid= pads numbers with spaces; Fields() strips them.
		// comm may contain spaces — join fields[3:] to preserve full name.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		uid, _ := strconv.Atoi(fields[2])
		name := strings.Join(fields[3:], " ")
		procs = append(procs, processInfo{
			PID: pid, PPID: ppid, UID: uid, Name: name,
		})
	}
	return procs, nil
}
