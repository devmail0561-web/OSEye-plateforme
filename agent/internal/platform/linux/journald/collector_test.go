//go:build linux

package journald

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

func requireJournalctl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("journalctl"); err != nil {
		t.Skip("journalctl not available")
	}
}

func TestJournaldCollector_Creation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := NewJournaldCollector(nil, -1, logger)
	if err != nil {
		t.Fatalf("NewJournaldCollector failed: %v", err)
	}
	if c.Name() != "journald" {
		t.Errorf("expected 'journald', got %s", c.Name())
	}
}

func TestJournaldCollector_SetThrottle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewJournaldCollector(nil, -1, logger)
	c.SetThrottle(0.25)
	h := c.Health()
	if h.ThrottlePct != 25.0 {
		t.Errorf("expected ThrottlePct 25, got %v", h.ThrottlePct)
	}
}

func TestJournaldCollector_Stop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewJournaldCollector(nil, -1, logger)
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() failed: %v", err)
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop() second call failed: %v", err)
	}
}

func TestJournaldCollector_ParseLine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewJournaldCollector(nil, -1, logger)

	line := []byte(`{"MESSAGE":"test message","_HOSTNAME":"myhost","PRIORITY":"6","_SYSTEMD_UNIT":"sshd.service","_PID":"1234","_COMM":"sshd"}`)
	event, err := c.parseJournalLine(line)
	if err != nil {
		t.Fatalf("parseJournalLine failed: %v", err)
	}
	if event.Source != "journald" {
		t.Errorf("expected source 'journald', got %s", event.Source)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(event.Raw, &payload); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}
	if payload["message"] != "test message" {
		t.Errorf("expected message 'test message', got %v", payload["message"])
	}
	if payload["hostname"] != "myhost" {
		t.Errorf("expected hostname 'myhost', got %v", payload["hostname"])
	}
	if payload["unit"] != "sshd.service" {
		t.Errorf("expected unit 'sshd.service', got %v", payload["unit"])
	}
}

func TestJournaldCollector_ParseInvalidLine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewJournaldCollector(nil, -1, logger)

	_, err := c.parseJournalLine([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestJournaldCollector_StartStop(t *testing.T) {
	requireJournalctl(t)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, _ := NewJournaldCollector(nil, 6, logger) // info and above

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan collector.RawEvent, 100)
	done := make(chan error, 1)
	go func() {
		done <- c.Start(ctx, out)
	}()

	select {
	case <-ctx.Done():
	case err := <-done:
		if err != nil {
			t.Logf("Start returned: %v", err)
		}
	}

	t.Logf("Received %d journald events", len(out))
}
