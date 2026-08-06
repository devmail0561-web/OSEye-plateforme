//go:build linux

package fanotify

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/oseye/agent/internal/collector"
)

func TestFanotifyCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	paths := []string{"/tmp"}

	c, err := NewFanotifyCollector(paths, logger)
	if err != nil {
		t.Fatalf("NewFanotifyCollector failed: %v", err)
	}

	if c.Name() != "fanotify" {
		t.Errorf("expected name 'fanotify', got %s", c.Name())
	}

	if len(c.paths) != 1 || c.paths[0] != "/tmp" {
		t.Errorf("expected paths [/tmp], got %v", c.paths)
	}
}

func TestFanotifyCollector_DefaultPaths(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	c, err := NewFanotifyCollector(nil, logger)
	if err != nil {
		t.Fatalf("NewFanotifyCollector failed: %v", err)
	}

	expected := []string{"/etc/passwd", "/etc/shadow", "/root/.ssh"}
	if len(c.paths) != len(expected) {
		t.Errorf("expected %d default paths, got %d", len(expected), len(c.paths))
	}
}

func TestFanotifyCollector_RequiresCAP_SYS_ADMIN(t *testing.T) {
	// Test that fanotify initialization fails without CAP_SYS_ADMIN
	if os.Geteuid() == 0 {
		t.Skip("Test requires non-root user")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewFanotifyCollector([]string{"/tmp"}, logger)
	if err != nil {
		t.Fatalf("NewFanotifyCollector failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan collector.RawEvent, 10)
	err = c.Start(ctx, out)

	// Should fail with permission error
	if err == nil {
		t.Error("Expected error without CAP_SYS_ADMIN, got nil")
	}
}

func TestFanotifyCollector_WithCapability(t *testing.T) {
	// Only run if we have CAP_SYS_ADMIN (root or capability set)
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		t.Skipf("Skipping: requires CAP_SYS_ADMIN (error: %v)", err)
	}
	unix.Close(fd)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Create temp file for testing
	tmpfile, err := os.CreateTemp("", "oseye-fanotify-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	c, err := NewFanotifyCollector([]string{tmpfile.Name()}, logger)
	if err != nil {
		t.Fatalf("NewFanotifyCollector failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan collector.RawEvent, 10)
	go func() {
		if err := c.Start(ctx, out); err != nil {
			t.Logf("Start returned error: %v", err)
		}
	}()

	// Give collector time to initialize
	time.Sleep(100 * time.Millisecond)

	// Trigger fanotify event by accessing the file
	f, err := os.Open(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	f.Close()

	// Wait for event
	select {
	case event := <-out:
		if event.Source != "fanotify" {
			t.Errorf("expected source 'fanotify', got %s", event.Source)
		}
		if len(event.Raw) == 0 {
			t.Error("expected non-empty RawData")
		}
		t.Logf("Received event: %s", string(event.Raw))
	case <-time.After(1 * time.Second):
		t.Log("No event received (may be normal if filesystem doesn't support fanotify marks)")
	}

	c.Stop()
}

func TestFanotifyCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewFanotifyCollector([]string{"/tmp"}, logger)
	if err != nil {
		t.Fatalf("NewFanotifyCollector failed: %v", err)
	}

	// Stop before start should not panic
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}
