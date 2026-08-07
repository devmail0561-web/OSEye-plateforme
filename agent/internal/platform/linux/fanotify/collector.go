//go:build linux

package fanotify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*FanotifyCollector)(nil)

type FanotifyCollector struct {
	name       string
	paths      []string
	fd         int
	closeOnce  sync.Once
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount atomic.Uint64
	errorCount atomic.Uint64
	running    atomic.Bool
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

func NewFanotifyCollector(paths []string, logger *slog.Logger) (*FanotifyCollector, error) {
	if len(paths) == 0 {
		paths = []string{"/etc/passwd", "/etc/shadow", "/root/.ssh"}
	}

	c := &FanotifyCollector{
		name:   "fanotify",
		paths:  paths,
		fd:     -1,
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *FanotifyCollector) Name() string { return c.name }

func (c *FanotifyCollector) SetThrottle(factor float64) {
	c.throttle.Store(factor)
}

func (c *FanotifyCollector) Health() collector.CollectorHealth {
	lastErr := ""
	if v := c.lastError.Load(); v != nil {
		lastErr = v.(string)
	}
	return collector.CollectorHealth{
		Running:     c.running.Load(),
		ErrorCount:  int64(c.errorCount.Load()),
		EventsTotal: int64(c.eventCount.Load()),
		ThrottlePct: c.throttle.Load().(float64) * 100,
		LastError:   lastErr,
	}
}

func (c *FanotifyCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	var err error
	c.fd, err = unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE,
	)
	if err != nil {
		c.lastError.Store(err.Error())
		c.errorCount.Add(1)
		return fmt.Errorf("fanotify_init: %w (requires CAP_SYS_ADMIN)", err)
	}

	for _, path := range c.paths {
		err = unix.FanotifyMark(c.fd, unix.FAN_MARK_ADD,
			unix.FAN_OPEN|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE|unix.FAN_ACCESS,
			unix.AT_FDCWD, path)
		if err != nil {
			c.logger.Warn("fanotify_mark failed", slog.String("path", path), slog.String("error", err.Error()))
			continue
		}
		c.logger.Info("fanotify watching", slog.String("path", path))
	}

	c.running.Store(true)
	go c.readLoop(ctx, out)

	<-ctx.Done()
	c.running.Store(false)
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	if c.fd >= 0 {
		c.closeOnce.Do(func() { unix.Close(c.fd) })
	}
	return nil
}

func (c *FanotifyCollector) Stop() error {
	c.running.Store(false)
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	if c.fd >= 0 {
		c.closeOnce.Do(func() { unix.Close(c.fd) })
	}
	return nil
}

func (c *FanotifyCollector) readLoop(ctx context.Context, out chan<- collector.RawEvent) {
	buf := make([]byte, 8192)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		n, err := unix.Read(c.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			c.logger.Error("fanotify read error", slog.String("error", err.Error()))
			c.lastError.Store(err.Error())
			c.errorCount.Add(1)
			return
		}

		// sizeof(struct fanotify_event_metadata) = 24 bytes on Linux
		// Hardcoded because unix.SizeofFanotifyEventMetadata not available in golang.org/x/sys/unix
		const fanotifyMetadataSize = 24
		if n < fanotifyMetadataSize {
			continue
		}

		offset := 0
		for offset < n {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
				break
			}

			path, _ := c.getPathFromFd(meta.Fd)
			if meta.Fd > 0 {
				unix.Close(int(meta.Fd))
			}

			event := c.buildRawEvent(meta, path)
			select {
			case out <- event:
				c.eventCount.Add(1)
			case <-ctx.Done():
				return
			}

			offset += int(meta.Event_len)
		}
	}
}

func (c *FanotifyCollector) getPathFromFd(fd int32) (string, error) {
	if fd < 0 {
		return "", fmt.Errorf("invalid fd")
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd), buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (c *FanotifyCollector) buildRawEvent(meta *unix.FanotifyEventMetadata, path string) collector.RawEvent {
	eventType := "unknown"
	if meta.Mask&unix.FAN_OPEN != 0 {
		eventType = "open"
	} else if meta.Mask&unix.FAN_ACCESS != 0 {
		eventType = "access"
	} else if meta.Mask&unix.FAN_MODIFY != 0 {
		eventType = "modify"
	} else if meta.Mask&unix.FAN_CLOSE_WRITE != 0 {
		eventType = "close_write"
	}

	payload := map[string]interface{}{
		"source":       "fanotify",
		"event_type":   eventType,
		"path":         path,
		"pid":          meta.Pid,
		"mask":         meta.Mask,
		"timestamp_ns": time.Now().UnixNano(),
	}

	rawJSON, _ := json.Marshal(payload)
	return collector.RawEvent{
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       rawJSON,
	}
}
