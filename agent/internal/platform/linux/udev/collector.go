//go:build linux

package udev

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*UdevCollector)(nil)

// UdevCollector monitors device add/remove events via /run/udev/monitor
// or by watching /sys/class/ with inotify as fallback.
type UdevCollector struct {
	name       string
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount atomic.Uint64
	errorCount atomic.Uint64
	running    atomic.Bool
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

func NewUdevCollector(logger *slog.Logger) (*UdevCollector, error) {
	c := &UdevCollector{
		name:   "udev",
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *UdevCollector) Name() string { return c.name }

func (c *UdevCollector) SetThrottle(factor float64) { c.throttle.Store(factor) }

func (c *UdevCollector) Health() collector.CollectorHealth {
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

func (c *UdevCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running.Store(true)
	defer c.running.Store(false)

	// Try udev netlink socket first, fall back to inotify on /sys/block + /sys/bus/usb
	if err := c.startNetlink(ctx, out); err != nil {
		c.logger.Warn("udev netlink unavailable, falling back to inotify", slog.String("error", err.Error()))
		return c.startInotify(ctx, out)
	}
	return nil
}

func (c *UdevCollector) Stop() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	return nil
}

// startNetlink reads udev events from the kernel netlink socket (NETLINK_KOBJECT_UEVENT).
func (c *UdevCollector) startNetlink(ctx context.Context, out chan<- collector.RawEvent) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 1, // UDEV_MONITOR_KERNEL group
	}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			c.lastError.Store(err.Error())
			c.errorCount.Add(1)
			return fmt.Errorf("recvfrom: %w", err)
		}

		event := c.parseUevent(buf[:n])
		if event == nil {
			continue
		}

		throttle, _ := c.throttle.Load().(float64)
		if throttle <= 0 {
			continue
		}

		select {
		case out <- *event:
			c.eventCount.Add(1)
		case <-ctx.Done():
			return nil
		}
	}
}

// parseUevent parses a kernel uevent message (newline-separated key=value pairs).
func (c *UdevCollector) parseUevent(data []byte) *collector.RawEvent {
	lines := strings.Split(string(data), "\x00")
	fields := make(map[string]string)
	for _, line := range lines {
		if idx := strings.IndexByte(line, '='); idx > 0 {
			fields[line[:idx]] = line[idx+1:]
		}
	}

	action := fields["ACTION"]
	if action == "" {
		return nil
	}

	payload := map[string]interface{}{
		"source":       "udev",
		"timestamp_ns": time.Now().UnixNano(),
		"action":       action,
		"devpath":      fields["DEVPATH"],
		"subsystem":    fields["SUBSYSTEM"],
		"devtype":      fields["DEVTYPE"],
		"devname":      fields["DEVNAME"],
		"product":      fields["PRODUCT"],
		"vendor":       fields["ID_VENDOR"],
		"model":        fields["ID_MODEL"],
	}

	raw, _ := json.Marshal(payload)
	ev := &collector.RawEvent{
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       raw,
	}
	return ev
}

// startInotify watches /sys/block and /sys/bus/usb/devices as fallback.
func (c *UdevCollector) startInotify(ctx context.Context, out chan<- collector.RawEvent) error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	defer unix.Close(fd)

	watchPaths := []string{"/sys/block", "/sys/bus/usb/devices"}
	wds := make(map[int]string)

	for _, path := range watchPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		wd, err := unix.InotifyAddWatch(fd, path, unix.IN_CREATE|unix.IN_DELETE)
		if err != nil {
			c.logger.Warn("inotify_add_watch failed", slog.String("path", path), slog.String("error", err.Error()))
			continue
		}
		wds[wd] = path
	}

	buf := make([]byte, unix.SizeofInotifyEvent*32+unix.PathMax)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}

		offset := 0
		for offset < n {
			event := (*unix.InotifyEvent)(unsafePtr(&buf[offset]))
			basePath := wds[int(event.Wd)]
			name := ""
			if event.Len > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
				name = strings.TrimRight(string(nameBytes), "\x00")
			}

			action := "add"
			if event.Mask&unix.IN_DELETE != 0 {
				action = "remove"
			}

			payload := map[string]interface{}{
				"source":       "udev",
				"timestamp_ns": time.Now().UnixNano(),
				"action":       action,
				"devpath":      filepath.Join(basePath, name),
				"subsystem":    filepath.Base(basePath),
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
				return nil
			}

			offset += unix.SizeofInotifyEvent + int(event.Len)
		}
	}
}

// readLines reads all lines from a file path (helper for /sys parsing).
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
