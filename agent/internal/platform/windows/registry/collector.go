//go:build windows

// Package registry monitors Windows Registry keys for changes.
// Uses RegNotifyChangeKeyValue in async mode (with a Windows Event object)
// so the goroutine remains responsive to context cancellation and Stop().
package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Default registry keys to monitor for persistence and tampering.
var defaultWatchKeys = []watchKey{
	{hive: registry.LOCAL_MACHINE, path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{hive: registry.LOCAL_MACHINE, path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`},
	{hive: registry.CURRENT_USER, path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`},
	{hive: registry.LOCAL_MACHINE, path: `SYSTEM\CurrentControlSet\Services`},
	{hive: registry.LOCAL_MACHINE, path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`},
}

type watchKey struct {
	hive registry.Key
	path string
}

// Collector monitors registry keys for value changes.
type Collector struct {
	logger   *slog.Logger
	keys     []watchKey
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(logger *slog.Logger) (*Collector, error) {
	c := &Collector{
		logger: logger,
		keys:   defaultWatchKeys,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	return c, nil
}

func (c *Collector) Name() string { return "registry" }

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

type registryEvent struct {
	Hive      string `json:"hive"`
	KeyPath   string `json:"key_path"`
	EventType string `json:"event_type"`
}

func hiveName(k registry.Key) string {
	switch k {
	case registry.LOCAL_MACHINE:
		return "HKLM"
	case registry.CURRENT_USER:
		return "HKCU"
	case registry.USERS:
		return "HKU"
	case registry.CLASSES_ROOT:
		return "HKCR"
	default:
		return "UNKNOWN"
	}
}

const (
	regNotifyChangeLastSet = 0x00000004
	regNotifyChangeName    = 0x00000001
)

// watchKeyAsync watches a single registry key using an async Event object so
// the goroutine does not block and can respond to context cancellation.
func (c *Collector) watchKeyAsync(ctx context.Context, wk watchKey, out chan<- collector.RawEvent) {
	k, err := registry.OpenKey(wk.hive, wk.path, registry.NOTIFY|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	// Create a manual-reset event to receive the registry notification.
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(ev)

	if err := registryNotifyAsync(k, true, regNotifyChangeLastSet|regNotifyChangeName, ev); err != nil {
		return
	}

	// Wait for registry change, context cancellation, or Stop().
	handles := []windows.Handle{ev}
	const waitMs = 2000 // 2-second timeout so we re-arm periodically
	for {
		code, err := windows.WaitForMultipleObjects(handles, false, waitMs)
		if err != nil {
			return
		}
		switch code {
		case windows.WAIT_OBJECT_0: // registry change fired
			// Re-arm before emitting to avoid missing rapid changes.
			_ = windows.ResetEvent(ev)
			_ = registryNotifyAsync(k, true, regNotifyChangeLastSet|regNotifyChangeName, ev)

			rev := registryEvent{
				Hive:      hiveName(wk.hive),
				KeyPath:   wk.path,
				EventType: "key_changed",
			}
			b, _ := json.Marshal(rev)
			select {
			case out <- collector.RawEvent{
				Source:    "registry",
				OS:        "windows",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
		case uint32(windows.WAIT_TIMEOUT):
			// Timeout — check for shutdown, then re-arm and continue.
		default:
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		if f, _ := c.throttle.Load().(float64); f <= 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	for _, wk := range c.keys {
		go c.watchKeyAsync(ctx, wk, out)
	}
	// Block until shutdown so the goroutine (and its sub-goroutines) stay alive.
	select {
	case <-ctx.Done():
	case <-c.stopCh:
	}
}
