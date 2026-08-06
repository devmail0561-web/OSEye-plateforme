//go:build linux

package inotify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*InotifyCollector)(nil)

// InotifyWatch represents a path to watch with inotify.
type InotifyWatch struct {
	Path      string
	Recursive bool
	Mask      uint32
}

// InotifyCollector monitors directory changes using inotify API.
type InotifyCollector struct {
	name       string
	watches    []InotifyWatch
	fd         int
	wds        map[int]string // watch descriptor -> path mapping
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount uint64
}

// NewInotifyCollector creates a new inotify collector.
func NewInotifyCollector(watches []InotifyWatch, logger *slog.Logger) (*InotifyCollector, error) {
	if len(watches) == 0 {
		watches = []InotifyWatch{
			{Path: "/tmp", Recursive: false, Mask: unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY},
		}
	}

	return &InotifyCollector{
		name:    "inotify",
		watches: watches,
		fd:      -1,
		wds:     make(map[int]string),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}, nil
}

func (c *InotifyCollector) Name() string {
	return c.name
}

func (c *InotifyCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	var err error
	c.fd, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init failed: %w", err)
	}

	for _, watch := range c.watches {
		if err := c.addWatch(watch); err != nil {
			c.logger.Warn("failed to add watch", slog.String("path", watch.Path), slog.String("error", err.Error()))
			continue
		}
	}

	go c.readLoop(ctx, out)

	<-ctx.Done()
	close(c.stopCh)
	if c.fd >= 0 {
		unix.Close(c.fd)
	}
	return nil
}

func (c *InotifyCollector) Stop() error {
	close(c.stopCh)
	if c.fd >= 0 {
		for wd := range c.wds {
			unix.InotifyRmWatch(c.fd, uint32(wd))
		}
		return unix.Close(c.fd)
	}
	return nil
}

func (c *InotifyCollector) addWatch(watch InotifyWatch) error {
	mask := watch.Mask
	if mask == 0 {
		mask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY | unix.IN_MOVED_FROM | unix.IN_MOVED_TO
	}

	wd, err := unix.InotifyAddWatch(c.fd, watch.Path, mask)
	if err != nil {
		return fmt.Errorf("inotify_add_watch(%s): %w", watch.Path, err)
	}

	c.wds[wd] = watch.Path
	c.logger.Info("inotify watching", slog.String("path", watch.Path), slog.Int("wd", wd))

	if watch.Recursive {
		return c.addRecursive(watch.Path, mask)
	}

	return nil
}

func (c *InotifyCollector) addRecursive(root string, mask uint32) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		if path == root {
			return nil
		}

		wd, err := unix.InotifyAddWatch(c.fd, path, mask)
		if err != nil {
			c.logger.Warn("failed to watch subdir", slog.String("path", path), slog.String("error", err.Error()))
			return nil
		}
		c.wds[wd] = path
		return nil
	})
}

func (c *InotifyCollector) readLoop(ctx context.Context, out chan<- collector.RawEvent) {
	buf := make([]byte, unix.SizeofInotifyEvent*16+unix.PathMax)

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
			c.logger.Error("inotify read error", slog.String("error", err.Error()))
			return
		}

		if n < unix.SizeofInotifyEvent {
			continue
		}

		offset := 0
		for offset < n {
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			name := ""
			if event.Len > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+int(event.Len)]
				name = string(bytes.TrimRight(nameBytes, "\x00"))
			}

			basePath := c.wds[int(event.Wd)]
			fullPath := filepath.Join(basePath, name)

			rawEvent := c.buildRawEvent(event, basePath, fullPath)
			select {
			case out <- rawEvent:
				c.eventCount++
			case <-ctx.Done():
				return
			}

			offset += unix.SizeofInotifyEvent + int(event.Len)
		}
	}
}

func (c *InotifyCollector) buildRawEvent(event *unix.InotifyEvent, basePath, fullPath string) collector.RawEvent {
	eventType := c.maskToType(event.Mask)

	payload := map[string]interface{}{
		"os":           "linux",
		"source":       "inotify",
		"event_type":   eventType,
		"wd":           event.Wd,
		"mask":         event.Mask,
		"cookie":       event.Cookie,
		"base_path":    basePath,
		"full_path":    fullPath,
		"timestamp_ns": time.Now().UnixNano(),
	}

	rawJSON, _ := json.Marshal(payload)

	return collector.RawEvent{
		Timestamp: time.Now(),
		Source:    c.name,
		RawData:   rawJSON,
	}
}

func (c *InotifyCollector) maskToType(mask uint32) string {
	switch {
	case mask&unix.IN_CREATE != 0:
		return "create"
	case mask&unix.IN_DELETE != 0:
		return "delete"
	case mask&unix.IN_MODIFY != 0:
		return "modify"
	case mask&unix.IN_MOVED_FROM != 0:
		return "moved_from"
	case mask&unix.IN_MOVED_TO != 0:
		return "moved_to"
	case mask&unix.IN_ATTRIB != 0:
		return "attrib"
	case mask&unix.IN_CLOSE_WRITE != 0:
		return "close_write"
	case mask&unix.IN_OPEN != 0:
		return "open"
	default:
		return "unknown"
	}
}
