//go:build linux

package inotify

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"github.com/oseye/agent/internal/collector"
)

func TestInotifyCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	watches := []InotifyWatch{
		{Path: "/tmp", Recursive: false, Mask: unix.IN_CREATE},
	}

	c, err := NewInotifyCollector(watches, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
	}

	if c.Name() != "inotify" {
		t.Errorf("expected name 'inotify', got %s", c.Name())
	}

	if len(c.watches) != 1 {
		t.Errorf("expected 1 watch, got %d", len(c.watches))
	}
}

func TestInotifyCollector_DefaultWatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	c, err := NewInotifyCollector(nil, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
	}

	if len(c.watches) == 0 {
		t.Error("expected default watch, got empty")
	}
}

func TestInotifyCollector_CreateEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Create temp directory
	tmpdir, err := os.MkdirTemp("", "oseye-inotify-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	watches := []InotifyWatch{
		{Path: tmpdir, Recursive: false, Mask: unix.IN_CREATE | unix.IN_DELETE},
	}

	c, err := NewInotifyCollector(watches, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
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

	// Create file to trigger event
	testFile := filepath.Join(tmpdir, "test-file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-out:
		if event.Source != "inotify" {
			t.Errorf("expected source 'inotify', got %s", event.Source)
		}
		if len(event.Raw) == 0 {
			t.Error("expected non-empty RawData")
		}
		t.Logf("Received event: %s", string(event.Raw))
	case <-time.After(1 * time.Second):
		t.Error("Did not receive create event within timeout")
	}

	c.Stop()
}

func TestInotifyCollector_DeleteEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tmpdir, err := os.MkdirTemp("", "oseye-inotify-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create file before starting collector
	testFile := filepath.Join(tmpdir, "test-file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	watches := []InotifyWatch{
		{Path: tmpdir, Recursive: false, Mask: unix.IN_DELETE},
	}

	c, err := NewInotifyCollector(watches, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan collector.RawEvent, 10)
	go func() {
		if err := c.Start(ctx, out); err != nil {
			t.Logf("Start returned error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Delete file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("Failed to delete test file: %v", err)
	}

	// Wait for event
	select {
	case event := <-out:
		if event.Source != "inotify" {
			t.Errorf("expected source 'inotify', got %s", event.Source)
		}
		t.Logf("Received delete event: %s", string(event.Raw))
	case <-time.After(1 * time.Second):
		t.Error("Did not receive delete event within timeout")
	}

	c.Stop()
}

func TestInotifyCollector_RecursiveWatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tmpdir, err := os.MkdirTemp("", "oseye-inotify-recursive-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create subdirectory structure
	subdir := filepath.Join(tmpdir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdir: %v", err)
	}

	watches := []InotifyWatch{
		{Path: tmpdir, Recursive: true, Mask: unix.IN_CREATE},
	}

	c, err := NewInotifyCollector(watches, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan collector.RawEvent, 10)
	go func() {
		if err := c.Start(ctx, out); err != nil {
			t.Logf("Start returned error: %v", err)
		}
	}()

	// Give collector time to initialize watches
	time.Sleep(100 * time.Millisecond)

	// Check that subdirectory is also watched
	if len(c.wds) < 2 {
		t.Logf("Warning: expected at least 2 watch descriptors (root + subdir), got %d", len(c.wds))
	}

	time.Sleep(100 * time.Millisecond)

	// Create file in subdirectory
	testFile := filepath.Join(subdir, "nested-file.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create nested file: %v", err)
	}

	// Should receive event from subdirectory
	select {
	case event := <-out:
		t.Logf("Received recursive event: %s", string(event.Raw))
	case <-time.After(1 * time.Second):
		t.Error("Did not receive event from subdirectory")
	}

	c.Stop()
}

func TestInotifyCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewInotifyCollector(nil, logger)
	if err != nil {
		t.Fatalf("NewInotifyCollector failed: %v", err)
	}

	// Stop before start should not panic
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
}

func TestInotifyCollector_MaskToType(t *testing.T) {
	c := &InotifyCollector{}

	tests := []struct {
		mask uint32
		want string
	}{
		{unix.IN_CREATE, "create"},
		{unix.IN_DELETE, "delete"},
		{unix.IN_MODIFY, "modify"},
		{unix.IN_MOVED_FROM, "moved_from"},
		{unix.IN_MOVED_TO, "moved_to"},
		{unix.IN_ATTRIB, "attrib"},
		{unix.IN_CLOSE_WRITE, "close_write"},
		{unix.IN_OPEN, "open"},
		{0, "unknown"},
	}

	for _, tt := range tests {
		got := c.maskToType(tt.mask)
		if got != tt.want {
			t.Errorf("maskToType(%d) = %s, want %s", tt.mask, got, tt.want)
		}
	}
}
