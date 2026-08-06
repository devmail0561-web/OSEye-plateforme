//go:build linux

package fanotify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"oseye/internal/collector"
)

var _ collector.Collector = (*FanotifyCollector)(nil)

// FanotifyCollector monitors file access/modification events using fanotify API.
type FanotifyCollector struct {
	name       string
	paths      []string
	fd         int
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount uint64
}

// NewFanotifyCollector creates a new fanotify collector.
// Requires CAP_SYS_ADMIN capability.
func NewFanotifyCollector(paths []string, logger *slog.Logger) (*FanotifyCollector, error) {
	if len(paths) == 0 {
		paths = []string{"/etc/passwd", "/etc/shadow", "/root/.ssh"}
	}

	return &FanotifyCollector{
		name:   "fanotify",
		paths:  paths,
		fd:     -1,
		logger: logger,
		stopCh: make(chan struct{}),
	}, nil
}

func (c *FanotifyCollector) Name() string {
	return c.name
}

func (c *FanotifyCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	var err error
	c.fd, err = unix.FanotifyInit(
		unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE,
	)
	if err != nil {
		return fmt.Errorf("fanotify_init failed: %w (requires CAP_SYS_ADMIN)", err)
	}

	for _, path := range c.paths {
		err = unix.FanotifyMark(
			c.fd,
			unix.FAN_MARK_ADD,
			unix.FAN_OPEN|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE|unix.FAN_ACCESS,
			unix.AT_FDCWD,
			path,
		)
		if err != nil {
			c.logger.Warn("fanotify_mark failed", slog.String("path", path), slog.String("error", err.Error()))
			continue
		}
		c.logger.Info("fanotify watching", slog.String("path", path))
	}

	go c.readLoop(ctx, out)

	<-ctx.Done()
	close(c.stopCh)
	if c.fd >= 0 {
		unix.Close(c.fd)
	}
	return nil
}

func (c *FanotifyCollector) Stop() error {
	close(c.stopCh)
	if c.fd >= 0 {
		return unix.Close(c.fd)
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
			return
		}

		if n < unix.SizeofFanotifyEventMetadata {
			continue
		}

		offset := 0
		for offset < n {
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
				c.logger.Warn("fanotify: invalid metadata version")
				break
			}

			path, _ := c.getPathFromFd(meta.Fd)
			if meta.Fd > 0 {
				unix.Close(int(meta.Fd))
			}

			event := c.buildRawEvent(meta, path)
			select {
			case out <- event:
				c.eventCount++
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
	linkPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := unix.Readlink(linkPath)
	if err != nil {
		return "", err
	}
	return path, nil
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
		"os":           "linux",
		"source":       "fanotify",
		"event_type":   eventType,
		"path":         path,
		"pid":          meta.Pid,
		"mask":         meta.Mask,
		"timestamp_ns": time.Now().UnixNano(),
	}

	rawJSON, _ := json.Marshal(payload)

	return collector.RawEvent{
		Timestamp: time.Now(),
		Source:    c.name,
		RawData:   rawJSON,
	}
}
