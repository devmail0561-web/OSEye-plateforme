//go:build linux

package udev

import (
	"log/slog"
	"os"
	"testing"
)

func TestUdevCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewUdevCollector(logger)
	if err != nil {
		t.Fatalf("NewUdevCollector failed: %v", err)
	}
	if c.Name() != "udev" {
		t.Errorf("expected 'udev', got %s", c.Name())
	}
}

func TestUdevCollector_SetThrottle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewUdevCollector(logger)
	c.SetThrottle(0.75)
	h := c.Health()
	if h.ThrottlePct != 75.0 {
		t.Errorf("expected ThrottlePct 75, got %v", h.ThrottlePct)
	}
}

func TestUdevCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewUdevCollector(logger)
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() second call failed: %v", err)
	}
}

func TestUdevCollector_ParseUevent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewUdevCollector(logger)

	// Simulate a kernel uevent message (null-separated key=value pairs)
	msg := "ACTION=add\x00DEVPATH=/devices/usb1/1-1\x00SUBSYSTEM=usb\x00DEVTYPE=usb_device\x00PRODUCT=1234/5678/0\x00"
	event := c.parseUevent([]byte(msg))
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Source != "udev" {
		t.Errorf("expected source 'udev', got %s", event.Source)
	}
	if event.OS != "linux" {
		t.Errorf("expected OS 'linux', got %s", event.OS)
	}
}

func TestUdevCollector_ParseUeventEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewUdevCollector(logger)

	event := c.parseUevent([]byte("KEY=value\x00NOACTION=here"))
	if event != nil {
		t.Error("expected nil event when ACTION is absent")
	}
}

func TestUdevCollector_Health(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewUdevCollector(logger)
	h := c.Health()
	if h.Running {
		t.Error("expected not running before Start")
	}
	if h.ErrorCount != 0 {
		t.Errorf("expected 0 errors, got %d", h.ErrorCount)
	}
}
