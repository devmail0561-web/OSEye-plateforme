//go:build windows

// Package fswatch monitors file system directories for changes using
// ReadDirectoryChangesW (synchronous mode), the Windows equivalent of inotify/fanotify.
package fswatch

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"golang.org/x/sys/windows"
)

// Default paths to watch — mapped from fanotify defaults.
var defaultPaths = []string{
	`C:\Windows\System32`,
	`C:\Users`,
	`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
}

// FILE_NOTIFY_INFORMATION mirrors Windows FILE_NOTIFY_INFORMATION structure.
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16
}

const (
	fileNotifyChangeFileName  = 0x00000001
	fileNotifyChangeDirName   = 0x00000002
	fileNotifyChangeLastWrite = 0x00000010
	fileNotifyChangeSecurity  = 0x00000100

	fileActionAdded          = 1
	fileActionRemoved        = 2
	fileActionModified       = 3
	fileActionRenamedOldName = 4
	fileActionRenamedNewName = 5

	notifyFilter = fileNotifyChangeFileName | fileNotifyChangeDirName |
		fileNotifyChangeLastWrite | fileNotifyChangeSecurity

	watchBufSize = 65536
	// maxFileNameU16 caps the UTF-16 slice to MAX_PATH units to prevent
	// an oversized FileNameLength from causing a slice-out-of-bounds panic.
	maxFileNameU16 = windows.MAX_PATH
)

// Collector watches directories for file system changes.
type Collector struct {
	logger   *slog.Logger
	paths    []string
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(paths []string, logger *slog.Logger) (*Collector, error) {
	if len(paths) == 0 {
		paths = defaultPaths
	}
	c := &Collector{
		logger: logger,
		paths:  paths,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "fswatch" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running = true
	for _, p := range c.paths {
		go c.watchPath(ctx, p, out)
	}
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

type fsEvent struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	EventType string `json:"event_type"`
	Action    uint32 `json:"action"`
}

func actionName(a uint32) string {
	switch a {
	case fileActionAdded:
		return "create"
	case fileActionRemoved:
		return "delete"
	case fileActionModified:
		return "modify"
	case fileActionRenamedOldName, fileActionRenamedNewName:
		return "rename"
	default:
		return "unknown"
	}
}

func (c *Collector) watchPath(ctx context.Context, path string, out chan<- collector.RawEvent) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		c.logger.Warn("fswatch: invalid path", "path", path, "err", err)
		return
	}

	// Use synchronous I/O (no FILE_FLAG_OVERLAPPED).
	// ReadDirectoryChanges with OVERLAPPED requires GetOverlappedResult /
	// completion ports; without that bytesReturned is always 0 and no events
	// are delivered. Synchronous mode blocks until at least one change occurs.
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // synchronous
		0,
	)
	if err != nil {
		c.logger.Warn("fswatch: open dir failed", "path", path, "err", err)
		return
	}
	defer windows.CloseHandle(handle)

	buf := make([]byte, watchBufSize)
	var bytesReturned uint32

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

		// Synchronous call — blocks until a change is detected or an error occurs.
		err := windows.ReadDirectoryChanges(
			handle,
			&buf[0],
			uint32(len(buf)),
			true, // watchSubtree
			notifyFilter,
			&bytesReturned,
			nil, // no overlapped
			0,
		)
		if err != nil {
			c.logger.Debug("fswatch: ReadDirectoryChanges error", "path", path, "err", err)
			time.Sleep(time.Second)
			continue
		}

		if bytesReturned == 0 {
			continue
		}

		offset := 0
		for offset < int(bytesReturned) {
			if offset+int(unsafe.Sizeof(fileNotifyInformation{})) > int(bytesReturned) {
				break
			}
			info := (*fileNotifyInformation)(unsafe.Pointer(&buf[offset]))

			// Cap nameLen to maxFileNameU16 to prevent oversized slice.
			nameLen := int(info.FileNameLength / 2)
			if nameLen <= 0 {
				if info.NextEntryOffset == 0 {
					break
				}
				offset += int(info.NextEntryOffset)
				continue
			}
			if nameLen > maxFileNameU16 {
				nameLen = maxFileNameU16
			}

			// Safely read the UTF-16 filename from the buffer.
			filenameOffset := offset + int(unsafe.Offsetof(info.FileName))
			if filenameOffset+nameLen*2 > int(bytesReturned) {
				break
			}
			nameSlice := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				nameSlice[i] = *(*uint16)(unsafe.Pointer(&buf[filenameOffset+i*2]))
			}
			name := windows.UTF16ToString(nameSlice)
			name = filepath.FromSlash(name)

			ev := fsEvent{
				Path:      strings.TrimRight(path, `\/`) + `\` + filepath.Dir(name),
				Name:      filepath.Base(name),
				EventType: actionName(info.Action),
				Action:    info.Action,
			}
			b, _ := json.Marshal(ev)
			select {
			case out <- collector.RawEvent{
				Source:    "fswatch",
				OS:        "windows",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}

			if info.NextEntryOffset == 0 {
				break
			}
			offset += int(info.NextEntryOffset)
		}
	}
}
