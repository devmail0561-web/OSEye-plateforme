package collector

import (
	"context"
	"sync"
)

// CollectorManager starts a set of Collectors, fans their events into a single
// channel, and provides aggregate health reporting.
type CollectorManager struct {
	collectors []Collector
	out        chan RawEvent
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewManager creates a CollectorManager over the given collectors.
// bufSize is the capacity of the fan-in output channel.
func NewManager(collectors []Collector, bufSize int) *CollectorManager {
	return &CollectorManager{
		collectors: collectors,
		out:        make(chan RawEvent, bufSize),
	}
}

// Start launches every collector in its own goroutine and returns immediately.
// Events from all collectors are multiplexed onto Events().
func (m *CollectorManager) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	for _, c := range m.collectors {
		c := c
		inner := make(chan RawEvent, 64)

		// Fan-in goroutine: forwards inner → m.out until inner is closed.
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for ev := range inner {
				select {
				case m.out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}()

		// Collector goroutine.
		m.wg.Add(1)
		go func() {
			defer func() {
				close(inner)
				m.wg.Done()
			}()
			_ = c.Start(ctx, inner)
		}()
	}

	// Close m.out once all goroutines finish.
	go func() {
		m.wg.Wait()
		close(m.out)
	}()

	return nil
}

// Stop cancels all collectors and waits for them to finish.
func (m *CollectorManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	for _, c := range m.collectors {
		_ = c.Stop()
	}
}

// Events returns the fan-in channel. Closed after Stop() and all goroutines exit.
func (m *CollectorManager) Events() <-chan RawEvent { return m.out }

// Healths returns the current health of every collector keyed by name.
func (m *CollectorManager) Healths() map[string]CollectorHealth {
	out := make(map[string]CollectorHealth, len(m.collectors))
	for _, c := range m.collectors {
		out[c.Name()] = c.Health()
	}
	return out
}
