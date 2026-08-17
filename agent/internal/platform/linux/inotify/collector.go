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
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
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
	fd         atomic.Int32
	closeOnce  sync.Once
	wdsMu      sync.RWMutex
	wds        map[int]string
	logger     *slog.Logger
	stopCh     chan struct{}
	eventCount atomic.Uint64
	errorCount atomic.Uint64
	running    atomic.Bool
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

// NewInotifyCollector creates a new inotify collector.
func NewInotifyCollector(watches []InotifyWatch, logger *slog.Logger) (*InotifyCollector, error) {
	if len(watches) == 0 {
		watches = []InotifyWatch{
			{Path: "/tmp", Recursive: false, Mask: unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY},
		}
	}

	c := &InotifyCollector{
		name:    "inotify",
		watches: watches,
		wds:     make(map[int]string),
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
	c.fd.Store(-1)
	c.throttle.Store(1.0)
	return c, nil
}

func (c *InotifyCollector) Name() string { return c.name }

func (c *InotifyCollector) SetThrottle(factor float64) {
	c.throttle.Store(factor)
}

func (c *InotifyCollector) Health() collector.CollectorHealth {
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

func (c *InotifyCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		c.lastError.Store(err.Error())
		c.errorCount.Add(1)
		return fmt.Errorf("inotify_init: %w", err)
	}
	c.fd.Store(int32(fd))

	for _, watch := range c.watches {
		if err := c.addWatch(watch); err != nil {
			c.logger.Warn("failed to add watch", slog.String("path", watch.Path), slog.String("error", err.Error()))
			continue
		}
	}

	c.running.Store(true)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.readLoop(ctx, out)
	}()

	<-ctx.Done()
	c.running.Store(false)
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	if fd := c.fd.Load(); fd >= 0 {
		c.closeOnce.Do(func() { unix.Close(int(c.fd.Load())) })
	}
	wg.Wait()
	return nil
}

func (c *InotifyCollector) Stop() error {
	c.running.Store(false)
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	if fd := c.fd.Load(); fd >= 0 {
		c.wdsMu.RLock()
		wds := make([]int, 0, len(c.wds))
		for wd := range c.wds {
			wds = append(wds, wd)
		}
		c.wdsMu.RUnlock()
		for _, wd := range wds {
			_, _ = unix.InotifyRmWatch(int(fd), uint32(wd))
		}
		c.closeOnce.Do(func() { unix.Close(int(c.fd.Load())) })
	}
	return nil
}

func (c *InotifyCollector) addWatch(watch InotifyWatch) error {
	mask := watch.Mask
	if mask == 0 {
		mask = unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY | unix.IN_MOVED_FROM | unix.IN_MOVED_TO
	}

	wd, err := unix.InotifyAddWatch(int(c.fd.Load()), watch.Path, mask)
	if err != nil {
		return fmt.Errorf("inotify_add_watch(%s): %w", watch.Path, err)
	}

	c.wdsMu.Lock()
	c.wds[wd] = watch.Path
	c.wdsMu.Unlock()
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

		wd, err := unix.InotifyAddWatch(int(c.fd.Load()), path, mask)
		if err != nil {
			c.logger.Warn("failed to watch subdir", slog.String("path", path), slog.String("error", err.Error()))
			return nil
		}
		c.wdsMu.Lock()
		c.wds[wd] = path
		c.wdsMu.Unlock()
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

		n, err := unix.Read(int(c.fd.Load()), buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			c.logger.Error("inotify read error", slog.String("error", err.Error()))
			c.lastError.Store(err.Error())
			c.errorCount.Add(1)
			return
		}

		if n < unix.SizeofInotifyEvent {
			continue
		}

		offset := 0
		for offset < n {
			if offset+unix.SizeofInotifyEvent > n {
				break
			}
			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

				name := ""
			if event.Len > 0 {
				end := offset + unix.SizeofInotifyEvent + int(event.Len)
				if end > n {
					break
				}
				nameBytes := buf[offset+unix.SizeofInotifyEvent : end]
				name = string(bytes.TrimRight(nameBytes, "\x00"))
			}

			c.wdsMu.RLock()
			basePath := c.wds[int(event.Wd)]
			c.wdsMu.RUnlock()
			fullPath := filepath.Join(basePath, name)

			rawEvent := c.buildRawEvent(event, basePath, fullPath)
			select {
			case out <- rawEvent:
				c.eventCount.Add(1)
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
		Source:    c.name,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       rawJSON,
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
