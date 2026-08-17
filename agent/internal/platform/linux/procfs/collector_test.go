//go:build linux

package procfs_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/platform/linux/procfs"
)

func TestProcfsCollector_EmitsEvents(t *testing.T) {
	c := procfs.New()
	out := make(chan collector.RawEvent, 256)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx, out) }()

	var ev collector.RawEvent
	select {
	case ev = <-out:
	case <-ctx.Done():
		t.Fatal("no event received within timeout")
	}

	if ev.Source != "procfs" {
		t.Errorf("Source = %q, want procfs", ev.Source)
	}
	if ev.OS != "linux" {
		t.Errorf("OS = %q, want linux", ev.OS)
	}
	if ev.Timestamp == 0 {
		t.Error("Timestamp is zero")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(ev.Raw, &payload); err != nil {
		t.Fatalf("invalid JSON payload: %v — raw: %s", err, ev.Raw)
	}
	for _, field := range []string{"event_type", "pid", "name"} {
		if _, ok := payload[field]; !ok {
			t.Errorf("payload missing field %q", field)
		}
	}

	if et, _ := payload["event_type"].(string); et != "process_create" {
		t.Errorf("event_type = %q, want process_create", et)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start did not return after context cancel")
	}
}

func TestProcfsCollector_Stop(t *testing.T) {
	c := procfs.New()
	out := make(chan collector.RawEvent, 256)
	ctx := context.Background()

	done := make(chan error, 1)
	go func() { done <- c.Start(ctx, out) }()

	// Let it emit at least one event.
	select {
	case <-out:
	case <-time.After(3 * time.Second):
		t.Fatal("no event before Stop")
	}

	if err := c.Stop(); err != nil {
		t.Errorf("Stop() = %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error after Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Start did not return after Stop")
	}
}

func TestProcfsCollector_Health(t *testing.T) {
	c := procfs.New()
	h := c.Health()
	if h.Running {
		t.Error("Health.Running should be false before Start")
	}
}

func TestProcfsCollector_Throttle(t *testing.T) {
	c := procfs.New()
	c.SetThrottle(0.5)
	// Just ensure no panic — actual timing is environment-dependent.
}
