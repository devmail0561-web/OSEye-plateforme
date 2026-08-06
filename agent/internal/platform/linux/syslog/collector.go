//go:build linux

package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*SyslogCollector)(nil)

// facilityNames maps syslog facility numbers to names.
var facilityNames = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog",
	"lpr", "news", "uucp", "cron", "authpriv", "ftp",
	"ntp", "security", "console", "clock",
	"local0", "local1", "local2", "local3",
	"local4", "local5", "local6", "local7",
}

// severityNames maps syslog severity numbers to names.
var severityNames = []string{
	"emergency", "alert", "critical", "error",
	"warning", "notice", "info", "debug",
}

// SyslogCollector listens on UDP 514 for syslog messages (RFC3164/RFC5424).
type SyslogCollector struct {
	name       string
	addr       string
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount atomic.Uint64
	errorCount atomic.Uint64
	running    atomic.Bool
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

func NewSyslogCollector(addr string, logger *slog.Logger) (*SyslogCollector, error) {
	if addr == "" {
		addr = "127.0.0.1:514"
	}
	c := &SyslogCollector{
		name:   "syslog",
		addr:   addr,
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *SyslogCollector) Name() string { return c.name }

func (c *SyslogCollector) SetThrottle(factor float64) { c.throttle.Store(factor) }

func (c *SyslogCollector) Health() collector.CollectorHealth {
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

func (c *SyslogCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running.Store(true)
	defer c.running.Store(false)

	conn, err := net.ListenPacket("udp", c.addr)
	if err != nil {
		c.lastError.Store(err.Error())
		c.errorCount.Add(1)
		return fmt.Errorf("syslog listen %s: %w", c.addr, err)
	}
	c.logger.Info("syslog listening", slog.String("addr", c.addr))

	buf := make([]byte, 64*1024)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-c.stopCh:
					return
				case <-ctx.Done():
					return
				default:
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					c.lastError.Store(err.Error())
					c.errorCount.Add(1)
					return // exit on persistent non-timeout error
				}
			}

			throttle, _ := c.throttle.Load().(float64)
			if throttle <= 0 {
				continue
			}

			event, err := c.parseMessage(buf[:n])
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
	}()

	select {
	case <-ctx.Done():
	case <-c.stopCh:
	case <-done:
	}

	conn.Close()
	<-done
	return nil
}

func (c *SyslogCollector) Stop() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

// parseMessage parses RFC3164 syslog messages.
// RFC5424 is not yet supported — messages with version field will be partially parsed.
func (c *SyslogCollector) parseMessage(data []byte) (collector.RawEvent, error) {
	msg := strings.TrimRight(string(data), "\n\r")
	if len(msg) == 0 {
		return collector.RawEvent{}, fmt.Errorf("empty message")
	}

	facility := "unknown"
	severity := "unknown"
	hostname := ""
	program := ""
	content := msg

	// Parse priority header: <PRI>
	if len(msg) > 3 && msg[0] == '<' {
		end := strings.IndexByte(msg, '>')
		if end > 0 {
			priStr := msg[1:end]
			pri := 0
			fmt.Sscanf(priStr, "%d", &pri)
			facNum := pri >> 3
			sevNum := pri & 0x7
			if facNum < len(facilityNames) {
				facility = facilityNames[facNum]
			}
			if sevNum < len(severityNames) {
				severity = severityNames[sevNum]
			}
			content = msg[end+1:]
		}
	}

	// Extract hostname and program from RFC3164 remainder:
	// TIMESTAMP(3 tokens) HOSTNAME PROGRAM[PID]: MSG
	// fields[0]=month, [1]=day, [2]=time, [3]=hostname, [4]=program...
	fields := strings.Fields(content)
	if len(fields) > 4 {
		hostname = fields[3]
		program = strings.SplitN(fields[4], "[", 2)[0]
		program = strings.TrimSuffix(program, ":")
	}

	payload := map[string]interface{}{
		"source":       "syslog",
		"timestamp_ns": time.Now().UnixNano(),
		"facility":     facility,
		"severity":     severity,
		"hostname":     hostname,
		"program":      program,
		"message":      content,
	}

	raw, _ := json.Marshal(payload)
	return collector.RawEvent{
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       raw,
	}, nil
}
