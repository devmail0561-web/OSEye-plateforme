//go:build linux

package netlink

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*NetlinkCollector)(nil)

// tcpState maps Linux TCP state codes to human-readable strings.
var tcpState = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

// NetlinkCollector monitors network connections by polling /proc/net/tcp and /proc/net/udp.
// It emits a RawEvent for each new or closed connection detected between polls.
type NetlinkCollector struct {
	name        string
	interval    time.Duration
	logger      *slog.Logger
	stopCh      chan struct{}
	eventCount  atomic.Uint64
	errorCount  atomic.Uint64
	running     atomic.Bool
	lastError   atomic.Value // string
	throttle    atomic.Value // float64
	// tracks known connections to emit only deltas
	known map[string]bool
}

func NewNetlinkCollector(interval time.Duration, logger *slog.Logger) (*NetlinkCollector, error) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	c := &NetlinkCollector{
		name:     "netlink",
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
		known:    make(map[string]bool),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *NetlinkCollector) Name() string { return c.name }

func (c *NetlinkCollector) SetThrottle(factor float64) { c.throttle.Store(factor) }

func (c *NetlinkCollector) Health() collector.CollectorHealth {
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

func (c *NetlinkCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	if !c.running.CompareAndSwap(false, true) {
		return fmt.Errorf("netlink collector already running")
	}
	defer c.running.Store(false)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		case <-ticker.C:
			c.poll(ctx, out)
		}
	}
}

func (c *NetlinkCollector) Stop() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

func (c *NetlinkCollector) poll(ctx context.Context, out chan<- collector.RawEvent) {
	current := make(map[string]bool)

	for _, proto := range []string{"tcp", "udp", "tcp6", "udp6"} {
		conns, err := c.parseProcNet(proto)
		if err != nil {
			c.logger.Warn("netlink poll error", slog.String("proto", proto), slog.String("error", err.Error()))
			c.lastError.Store(err.Error())
			c.errorCount.Add(1)
			continue
		}

		for _, conn := range conns {
			// Use "|" separator — safe since it never appears in IP:port strings
			key := fmt.Sprintf("%s|%s|%s", proto, conn["local_addr"], conn["remote_addr"])
			current[key] = true

			if !c.known[key] {
				conn["event"] = "new"
				conn["proto"] = proto
				c.emit(ctx, out, conn)
			}
		}
	}

	// emit closed connections
	for key := range c.known {
		if !current[key] {
			parts := strings.SplitN(key, "|", 3)
			if len(parts) == 3 {
				c.emit(ctx, out, map[string]string{
					"event":       "closed",
					"proto":       parts[0],
					"local_addr":  parts[1],
					"remote_addr": parts[2],
				})
			}
		}
	}

	c.known = current
}

func (c *NetlinkCollector) emit(ctx context.Context, out chan<- collector.RawEvent, data map[string]string) {
	throttle, _ := c.throttle.Load().(float64)
	if throttle <= 0 {
		return
	}

	payload := map[string]interface{}{
		"source":       "netlink",
		"timestamp_ns": time.Now().UnixNano(),
	}
	for k, v := range data {
		payload[k] = v
	}

	raw, _ := json.Marshal(payload)
	select {
	case out <- collector.RawEvent{
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       raw,
	}:
		c.eventCount.Add(1)
	case <-ctx.Done():
	}
}

// parseProcNet reads /proc/net/<proto> and returns a slice of connection maps.
func (c *NetlinkCollector) parseProcNet(proto string) ([]map[string]string, error) {
	path := fmt.Sprintf("/proc/net/%s", proto)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []map[string]string
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		localAddr := hexToAddr(fields[1])
		remoteAddr := hexToAddr(fields[2])
		stateHex := strings.ToUpper(fields[3])
		state := tcpState[stateHex]
		if state == "" {
			state = stateHex
		}

		// skip LISTEN and empty remote for udp
		if state == "LISTEN" || remoteAddr == "0.0.0.0:0" || remoteAddr == "[::]:0" {
			continue
		}

		conns = append(conns, map[string]string{
			"local_addr":  localAddr,
			"remote_addr": remoteAddr,
			"state":       state,
		})
	}
	return conns, scanner.Err()
}

// decodeIPv6Hex decodes a 32-char hex string from /proc/net/tcp6 into a 16-byte IPv6 address.
func decodeIPv6Hex(s string) ([]byte, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("invalid IPv6 hex length: %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	// /proc/net/tcp6 stores each 32-bit word in little-endian order
	for i := 0; i < 16; i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return b, nil
}

// hexToAddr converts a /proc/net hex address (e.g. "0101007F:0050") to "127.0.0.1:80".
func hexToAddr(hexAddr string) string {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return hexAddr
	}

	addrHex, portHex := parts[0], parts[1]
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return hexAddr
	}

	// IPv6 addresses are 32 hex chars (16 bytes)
	if len(addrHex) > 8 {
		b, err := decodeIPv6Hex(addrHex)
		if err != nil {
			return fmt.Sprintf("[%s]:%d", addrHex, port)
		}
		return fmt.Sprintf("[%s]:%d", net.IP(b).String(), port)
	}

	// IPv4: little-endian 32-bit hex
	n, err := strconv.ParseUint(addrHex, 16, 32)
	if err != nil {
		return hexAddr
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d",
		n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff, port)
}
