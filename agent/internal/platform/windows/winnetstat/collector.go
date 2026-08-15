//go:build windows

// Package winnetstat collects TCP/UDP connections by parsing
// netstat -ano output, equivalent to the Linux netlink collector.
package winnetstat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

const scanInterval = 10 * time.Second

// Collector periodically scans network connections via netstat.
type Collector struct {
	logger   *slog.Logger
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(logger *slog.Logger) (*Collector, error) {
	c := &Collector{
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "winnetstat" }

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

type netConn struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
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
			conns, err := c.scan(ctx)
			if err != nil {
				c.logger.Debug("winnetstat scan error", "err", err)
				continue
			}
			for _, conn := range conns {
				b, _ := json.Marshal(conn)
				select {
				case out <- collector.RawEvent{
					Source:    "winnetstat",
					OS:        "windows",
					Timestamp: time.Now().UnixNano(),
					Raw:       b,
				}:
				default:
				}
			}
		}
	}
}

func (c *Collector) scan(ctx context.Context) ([]netConn, error) {
	cmd := exec.CommandContext(ctx, "netstat", "-ano", "-p", "TCP")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var conns []netConn
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "TCP") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// fields: Proto LocalAddr ForeignAddr State PID
		local := parseAddr(fields[1])
		remote := parseAddr(fields[2])
		state := fields[3]
		pid, _ := strconv.Atoi(fields[4])

		conns = append(conns, netConn{
			Proto:      "tcp",
			LocalAddr:  local[0],
			LocalPort:  parsePort(local[1]),
			RemoteAddr: remote[0],
			RemotePort: parsePort(remote[1]),
			State:      state,
			PID:        pid,
		})
	}
	return conns, nil
}

// parseAddr splits "1.2.3.4:5678" or "[::1]:5678" into [addr, port].
func parseAddr(s string) [2]string {
	if strings.HasPrefix(s, "[") {
		// IPv6 [::1]:port
		idx := strings.LastIndex(s, "]:")
		if idx < 0 {
			return [2]string{s, "0"}
		}
		return [2]string{s[1:idx], s[idx+2:]}
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return [2]string{s, "0"}
	}
	return [2]string{s[:idx], s[idx+1:]}
}

func parsePort(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
