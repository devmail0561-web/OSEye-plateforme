package collector_test

import (
	"context"
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

// mockCollector emits a fixed number of events then blocks until stopped.
type mockCollector struct {
	name   string
	events []RawEvent
}

type RawEvent = collector.RawEvent

func (m *mockCollector) Name() string          { return m.name }
func (m *mockCollector) Stop() error           { return nil }
func (m *mockCollector) SetThrottle(_ float64) {}
func (m *mockCollector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: true}
}
func (m *mockCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	for _, ev := range m.events {
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
	<-ctx.Done()
	return nil
}

func TestManager_FanIn(t *testing.T) {
	evA := collector.RawEvent{Source: "a", OS: "linux", Raw: []byte(`{"a":1}`)}
	evB := collector.RawEvent{Source: "b", OS: "linux", Raw: []byte(`{"b":2}`)}

	ca := &mockCollector{name: "a", events: []collector.RawEvent{evA}}
	cb := &mockCollector{name: "b", events: []collector.RawEvent{evB}}

	mgr := collector.NewManager([]collector.Collector{ca, cb}, 16)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case ev, ok := <-mgr.Events():
			if !ok {
				t.Fatal("channel closed too early")
			}
			got[ev.Source] = true
		case <-ctx.Done():
			t.Fatal("timeout waiting for events")
		}
	}
	if !got["a"] || !got["b"] {
		t.Errorf("expected events from both collectors, got %v", got)
	}
}

func TestManager_Healths(t *testing.T) {
	ca := &mockCollector{name: "alpha", events: nil}
	cb := &mockCollector{name: "beta", events: nil}

	mgr := collector.NewManager([]collector.Collector{ca, cb}, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	defer mgr.Stop()

	h := mgr.Healths()
	if _, ok := h["alpha"]; !ok {
		t.Error("missing health for alpha")
	}
	if _, ok := h["beta"]; !ok {
		t.Error("missing health for beta")
	}
}

func TestManager_Stop(t *testing.T) {
	ca := &mockCollector{name: "a", events: nil}
	mgr := collector.NewManager([]collector.Collector{ca}, 4)

	ctx := context.Background()
	_ = mgr.Start(ctx)
	mgr.Stop()

	// After Stop, Events() channel should close eventually.
	select {
	case _, ok := <-mgr.Events():
		if ok {
			// drain until closed
			for range mgr.Events() {
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("channel did not close after Stop")
	}
}
