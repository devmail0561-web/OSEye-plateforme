//go:build linux

package autonomy

import (
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

const defaultSentinelPath = "/etc/oseye/disable_autonomy"

// KillSwitch provides emergency disablement of the autonomy controller.
// It checks both an atomic flag (set via server command) and a sentinel file.
type KillSwitch struct {
	disabled     atomic.Bool
	sentinelPath string

	// Cached sentinel check to avoid stat() on every event.
	sentinelCached atomic.Bool
	lastCheck      atomic.Int64
}

const sentinelCheckInterval = 2 // seconds

// NewKillSwitch creates a new kill switch with the default sentinel path.
func NewKillSwitch() *KillSwitch {
	ks := &KillSwitch{
		sentinelPath: defaultSentinelPath,
	}
	// Check if already disabled at startup.
	if _, err := os.Stat(ks.sentinelPath); err == nil {
		ks.disabled.Store(true)
		ks.sentinelCached.Store(true)
		slog.Warn("autonomy: kill switch active (sentinel file exists)", "path", ks.sentinelPath)
	}
	return ks
}

// Disable disables autonomy immediately (server command DISABLE_AUTONOMY).
func (ks *KillSwitch) Disable() {
	ks.disabled.Store(true)
	slog.Warn("autonomy: disabled by server command")
}

// Enable re-enables autonomy.
func (ks *KillSwitch) Enable() {
	ks.disabled.Store(false)
	ks.sentinelCached.Store(false)
	slog.Info("autonomy: re-enabled")
}

// IsDisabled returns true if autonomy is disabled by either the atomic flag
// or the sentinel file on disk. The sentinel file is checked at most once
// every 2 seconds to avoid excessive syscalls on the hot path.
func (ks *KillSwitch) IsDisabled() bool {
	if ks.disabled.Load() {
		return true
	}

	// Rate-limited sentinel file check.
	now := time.Now().Unix()
	last := ks.lastCheck.Load()
	if now-last >= sentinelCheckInterval {
		if ks.lastCheck.CompareAndSwap(last, now) {
			exists := false
			if _, err := os.Stat(ks.sentinelPath); err == nil {
				exists = true
			}
			ks.sentinelCached.Store(exists)
		}
	}
	return ks.sentinelCached.Load()
}
