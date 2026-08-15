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
// Each collector writes directly to m.out — no fan-in goroutine needed since
// all collector implementations already handle ctx.Done() on channel send.
func (m *CollectorManager) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	for _, c := range m.collectors {
		c := c
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			_ = c.Start(ctx, m.out)
		}()
	}

	// Close m.out once all collector goroutines have exited.
	go func() {
		m.wg.Wait()
		close(m.out)
	}()

	return nil
}

// Stop cancels all collectors and waits for all goroutines to exit.
// CORE-006: m.wg.Wait() ensures no goroutine is still writing to m.out or to
// collector-owned channels after Stop() returns, preventing use-after-close races.
func (m *CollectorManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	for _, c := range m.collectors {
		_ = c.Stop()
	}
	m.wg.Wait()
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

// SetThrottle propagates a throttle factor to every managed collector.
// The factor is clamped to [0.0, 1.0].
func (m *CollectorManager) SetThrottle(factor float64) {
	if factor < 0 {
		factor = 0
	}
	if factor > 1 {
		factor = 1
	}
	for _, c := range m.collectors {
		c.SetThrottle(factor)
	}
}
