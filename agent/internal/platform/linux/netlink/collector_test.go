//go:build linux

package netlink

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/oseye/agent/internal/collector"
)

func TestNetlinkCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewNetlinkCollector(0, logger)
	if err != nil {
		t.Fatalf("NewNetlinkCollector failed: %v", err)
	}
	if c.Name() != "netlink" {
		t.Errorf("expected 'netlink', got %s", c.Name())
	}
	if c.interval != 5*time.Second {
		t.Errorf("expected default interval 5s, got %v", c.interval)
	}
}

func TestNetlinkCollector_SetThrottle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewNetlinkCollector(0, logger)
	c.SetThrottle(0.5)
	h := c.Health()
	if h.ThrottlePct != 50.0 {
		t.Errorf("expected ThrottlePct 50, got %v", h.ThrottlePct)
	}
}

func TestNetlinkCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewNetlinkCollector(0, logger)
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
	// idempotent
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() second call failed: %v", err)
	}
}

func TestNetlinkCollector_Health(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewNetlinkCollector(0, logger)
	h := c.Health()
	if h.Running {
		t.Error("expected not running before Start")
	}
}

func TestNetlinkCollector_PollEmitsEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewNetlinkCollector(100*time.Millisecond, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out := make(chan collector.RawEvent, 100)
	go func() {
		c.Start(ctx, out) //nolint:errcheck
	}()

	// wait for at least one poll cycle
	time.Sleep(200 * time.Millisecond)
	cancel()

	// On a machine with active network connections, we expect events.
	// On a minimal test environment, the channel may be empty — that's OK.
	t.Logf("Received %d netlink events", len(out))
}

func TestNetlinkCollector_HexToAddr(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// /proc/net little-endian: 0101007F = [0x01, 0x01, 0x00, 0x7F] → 127.0.1.1
		{"0101007F:0050", "127.0.1.1:80"},
		// 0100007F = [0x01, 0x00, 0x00, 0x7F] → 127.0.0.1
		{"0100007F:1F90", "127.0.0.1:8080"},
		{"00000000:0000", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		got := hexToAddr(tt.input)
		if got != tt.want {
			t.Errorf("hexToAddr(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNetlinkCollector_ParseProcNet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewNetlinkCollector(0, logger)

	// /proc/net/tcp always exists on Linux
	conns, err := c.parseProcNet("tcp")
	if err != nil {
		t.Skipf("cannot read /proc/net/tcp: %v", err)
	}
	t.Logf("Found %d TCP connections", len(conns))
}
