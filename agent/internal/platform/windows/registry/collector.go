//go:build windows

// Package registry monitors Windows Registry keys for changes using
// RegNotifyChangeKeyValue. Watches HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
// and other persistence-relevant keys by default.
package registry

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
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

// notifyFilter: notify on value changes and sub-key changes
const regNotifyChangeLastSet = 0x00000004
const regNotifyChangeName = 0x00000001

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	for {
		if f, _ := c.throttle.Load().(float64); f <= 0 {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}

		for _, wk := range c.keys {
			select {
			case <-ctx.Done():
				return
			case <-c.stopCh:
				return
			default:
			}

			k, err := registry.OpenKey(wk.hive, wk.path, registry.NOTIFY|registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			// RegNotifyChangeKeyValue with bWatchSubtree=true
			err = registryNotify(k, true, regNotifyChangeLastSet|regNotifyChangeName, false)
			k.Close()
			if err != nil {
				continue
			}

			ev := registryEvent{
				Hive:      hiveName(wk.hive),
				KeyPath:   wk.path,
				EventType: "key_changed",
			}
			b, _ := json.Marshal(ev)
			select {
			case out <- collector.RawEvent{
				Source:    "registry",
				OS:        "windows",
				Timestamp: time.Now().UnixNano(),
				Raw:       b,
			}:
			default:
			}
		}

		// Brief pause between scans to avoid CPU spin
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}
