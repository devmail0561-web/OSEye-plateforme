//go:build windows

// Package toolhelp32 collects a periodic process snapshot using the Windows
// Toolhelp32 API (CreateToolhelp32Snapshot + Process32First/Next).
package toolhelp32

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/oseye/agent/internal/collector"
	"golang.org/x/sys/windows"
)

const (
	th32csSnapprocess = 0x00000002
	scanInterval      = 5 * time.Second
)

// processEntry32 mirrors PROCESSENTRY32W from the Windows SDK.
type processEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [windows.MAX_PATH]uint16
}

// Collector gathers process snapshots from the Windows kernel.
type Collector struct {
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New() *Collector {
	c := &Collector{stopCh: make(chan struct{})}
	c.throttle.Store(1.0)
	return c
}

func (c *Collector) Name() string { return "toolhelp32" }

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
			procs, err := snapshot()
			if err != nil {
				slog.Warn("toolhelp32 snapshot error", "err", err)
				continue
			}
			for _, p := range procs {
				b, _ := json.Marshal(p)
				select {
				case out <- collector.RawEvent{
					Source:    "toolhelp32",
					OS:        "windows",
					Timestamp: time.Now().UnixNano(),
					Raw:       b,
				}:
				default:
				}
			}
		}
	}
}

type processInfo struct {
	PID     uint32 `json:"pid"`
	PPID    uint32 `json:"ppid"`
	Name    string `json:"name"`
	Threads uint32 `json:"threads"`
}

var (
	modkernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32.NewProc("Process32NextW")
)

func snapshot() ([]processInfo, error) {
	h, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapprocess, 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, err
	}
	defer windows.CloseHandle(windows.Handle(h))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return nil, nil
	}

	var procs []processInfo
	for {
		procs = append(procs, processInfo{
			PID:     entry.ProcessID,
			PPID:    entry.ParentProcessID,
			Name:    windows.UTF16ToString(entry.ExeFile[:]),
			Threads: entry.Threads,
		})
		r, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return procs, nil
}
