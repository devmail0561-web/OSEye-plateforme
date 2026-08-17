//go:build darwin

// Package darwinnet collects TCP/UDP connections on macOS via netstat,
// equivalent to the Linux netlink collector.
package darwinnet

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

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

const scanInterval = 10 * time.Second

// Collector periodically scans network connections.
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

func (c *Collector) Name() string { return "darwinnet" }

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
			conns, err := scan(ctx)
			if err != nil {
				c.logger.Debug("darwinnet scan error", "err", err)
				continue
			}
			for _, conn := range conns {
				b, _ := json.Marshal(conn)
				select {
				case out <- collector.RawEvent{
					Source:    "darwinnet",
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

// scan runs `netstat -an -p tcp` and parses the output.
// macOS netstat format: Proto RecvQ SendQ LocalAddr ForeignAddr State
func scan(ctx context.Context) ([]netConn, error) {
	cmd := exec.CommandContext(ctx, "netstat", "-an", "-p", "tcp")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var conns []netConn
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "tcp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Proto RecvQ SendQ LocalAddr ForeignAddr State
		local := splitAddr(fields[3])
		remote := splitAddr(fields[4])
		state := fields[5]

		conns = append(conns, netConn{
			Proto:      fields[0],
			LocalAddr:  local[0],
			LocalPort:  portNum(local[1]),
			RemoteAddr: remote[0],
			RemotePort: portNum(remote[1]),
			State:      state,
		})
	}
	return conns, nil
}

// splitAddr splits "1.2.3.4.5678" (macOS netstat uses dots) or "[::1].5678"
func splitAddr(s string) [2]string {
	// macOS uses "." as separator for port: "192.168.1.1.80" or "*.80"
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return [2]string{s, "0"}
	}
	return [2]string{s[:idx], s[idx+1:]}
}

func portNum(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
