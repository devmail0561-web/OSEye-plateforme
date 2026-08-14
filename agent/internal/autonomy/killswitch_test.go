//go:build linux

package autonomy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKillSwitchDefault(t *testing.T) {
	ks := &KillSwitch{sentinelPath: filepath.Join(t.TempDir(), "disable_autonomy")}
	if ks.IsDisabled() {
		t.Error("expected kill switch to be inactive by default")
	}
}

func TestKillSwitchDisableEnable(t *testing.T) {
	ks := &KillSwitch{sentinelPath: filepath.Join(t.TempDir(), "disable_autonomy")}

	ks.Disable()
	if !ks.IsDisabled() {
		t.Error("expected kill switch to be active after Disable()")
	}

	ks.Enable()
	if ks.IsDisabled() {
		t.Error("expected kill switch to be inactive after Enable()")
	}
}

func TestKillSwitchSentinelFile(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "disable_autonomy")
	ks := &KillSwitch{sentinelPath: sentinel}

	// No file → active.
	if ks.IsDisabled() {
		t.Error("should not be disabled without sentinel file")
	}

	// Create sentinel file → disabled.
	// Force cache refresh by resetting lastCheck.
	if err := os.WriteFile(sentinel, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	ks.lastCheck.Store(0)
	if !ks.IsDisabled() {
		t.Error("expected disabled when sentinel file exists")
	}

	// Remove file → active again.
	os.Remove(sentinel)
	ks.lastCheck.Store(0)
	if ks.IsDisabled() {
		t.Error("should not be disabled after sentinel file removed")
	}
}
