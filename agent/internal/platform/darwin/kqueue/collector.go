//go:build darwin

// Package kqueue watches file system paths for changes on macOS using the
// kqueue(2) interface, the POSIX-compatible alternative to inotify.
package kqueue

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
	"golang.org/x/sys/unix"
)

// NOTE_* constants for kqueue vnode events
const (
	noteDelete = unix.NOTE_DELETE
	noteWrite  = unix.NOTE_WRITE
	noteExtend = unix.NOTE_EXTEND
	noteAttrib = unix.NOTE_ATTRIB
	noteRename = unix.NOTE_RENAME
	noteRevoke = unix.NOTE_REVOKE
	noteAll    = noteDelete | noteWrite | noteExtend | noteAttrib | noteRename | noteRevoke
)

var defaultPaths = []string{
	"/etc",
	"/usr/local/bin",
	"/Library/LaunchAgents",
	"/Library/LaunchDaemons",
	"/private/tmp",
}

// Collector watches paths via kqueue.
type Collector struct {
	logger   *slog.Logger
	paths    []string
	kq       int
	watches  map[int]string // fd → path
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(paths []string, logger *slog.Logger) (*Collector, error) {
	if len(paths) == 0 {
		paths = defaultPaths
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	c := &Collector{
		logger:  logger,
		paths:   paths,
		kq:      kq,
		watches: make(map[int]string),
		stopCh:  make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "kqueue" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	if err := c.registerPaths(); err != nil {
		return err
	}
	c.running = true
	go c.run(ctx, out)
	return nil
}

func (c *Collector) Stop() error {
	if c.running {
		close(c.stopCh)
		c.running = false
		for fd := range c.watches {
			unix.Close(fd)
		}
		unix.Close(c.kq)
	}
	return nil
}

func (c *Collector) SetThrottle(f float64) { c.throttle.Store(f) }

func (c *Collector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: c.running}
}

type kqueueEvent struct {
	Path      string `json:"path"`
	EventType string `json:"event_type"`
	Flags     uint32 `json:"flags"`
}

func flagsToType(flags uint32) string {
	switch {
	case flags&noteDelete != 0:
		return "delete"
	case flags&noteWrite != 0:
		return "write"
	case flags&noteRename != 0:
		return "rename"
	case flags&noteAttrib != 0:
		return "attrib"
	default:
		return "change"
	}
}

func (c *Collector) registerPaths() error {
	for _, p := range c.paths {
		// Walk directory to register files and subdirs
		filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return nil
			}
			kev := unix.Kevent_t{}
			unix.SetKevent(&kev, fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR)
			kev.Fflags = noteAll
			_, err = unix.Kevent(c.kq, []unix.Kevent_t{kev}, nil, nil)
			if err != nil {
				unix.Close(fd)
				return nil
			}
			c.watches[fd] = path
			return nil
		})
	}
	return nil
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	events := make([]unix.Kevent_t, 64)
	timeout := &unix.Timespec{Nsec: 500_000_000} // 500ms

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		if f, _ := c.throttle.Load().(float64); f <= 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		n, err := unix.Kevent(c.kq, nil, events, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		for i := 0; i < n; i++ {
			ev := &events[i]
			path, ok := c.watches[int(ev.Ident)]
			if !ok {
				continue
			}
			ke := kqueueEvent{
				Path:      path,
				EventType: flagsToType(uint32(ev.Fflags)),
				Flags:     uint32(ev.Fflags),
			}
			b, _ := json.Marshal(ke)
			select {
			case out <- collector.RawEvent{
				Source:    "kqueue",
				OS:        "darwin",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
		}
	}
}
