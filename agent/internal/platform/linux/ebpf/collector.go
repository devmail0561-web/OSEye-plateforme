//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/oseye/agent/internal/collector"
)

var _ collector.Collector = (*EBPFCollector)(nil)

// EBPFCollector attaches three eBPF tracepoints (execve, openat, connect) and
// forwards captured events as RawEvents. If the kernel does not support eBPF
// or CAP_BPF is absent, Start() logs a warning and returns nil so the agent
// continues running with the remaining collectors.
type EBPFCollector struct {
	mu         sync.Mutex
	loader     *EBPFLoader
	stopCh     chan struct{}
	running    atomic.Bool
	eventCount atomic.Int64
	errorCount atomic.Int64
	lastError  atomic.Value // string
	throttle   atomic.Value // float64
}

// New returns an EBPFCollector. The eBPF loader is created lazily in Start().
func New() *EBPFCollector {
	c := &EBPFCollector{stopCh: make(chan struct{})}
	c.throttle.Store(1.0)
	return c
}

func (c *EBPFCollector) Name() string { return "ebpf" }

// Start loads the eBPF programs and forwards events until ctx is cancelled or
// Stop is called. If loading fails (no CAP_BPF, kernel too old), it logs a
// warning and returns nil — graceful degradation.
func (c *EBPFCollector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	loader, err := NewLoader()
	if err != nil {
		slog.Warn("ebpf: loader unavailable — collector disabled", "err", err)
		return nil
	}
	c.mu.Lock()
	c.loader = loader
	// Recreate stopCh so Start() works correctly after a previous Stop() call.
	// Capture a local reference used in select statements to avoid data races
	// on the c.stopCh field after the mutex is released.
	c.stopCh = make(chan struct{})
	stopCh := c.stopCh
	c.mu.Unlock()
	defer func() {
		loader.Close()
		c.mu.Lock()
		c.loader = nil
		c.mu.Unlock()
	}()

	c.running.Store(true)
	defer c.running.Store(false)

	events := loader.ReadEvents(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-stopCh:
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}

			throttle, _ := c.throttle.Load().(float64)
			if throttle <= 0 {
				continue
			}

			raw, err := MarshalEvent(ev)
			if err != nil {
				c.errorCount.Add(1)
				c.lastError.Store(err.Error())
				continue
			}

			c.eventCount.Add(1)
			select {
			case out <- collector.RawEvent{
				Source:    "ebpf",
				OS:        "linux",
				Timestamp: int64(ev.TimestampNs),
				Raw:       raw,
			}:
			case <-ctx.Done():
				return nil
			case <-stopCh:
				return nil
			}
		}
	}
}

// Stop signals the collector to stop. Idempotent.
func (c *EBPFCollector) Stop() error {
	c.mu.Lock()
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	ldr := c.loader
	c.mu.Unlock()
	if ldr != nil {
		ldr.Close()
	}
	return nil
}

// SetThrottle implements collector.Collector. 0.0 = paused, 1.0 = full speed.
func (c *EBPFCollector) SetThrottle(factor float64) {
	c.throttle.Store(factor)
}

// Health implements collector.Collector.
func (c *EBPFCollector) Health() collector.CollectorHealth {
	lastErr, _ := c.lastError.Load().(string)
	throttle, _ := c.throttle.Load().(float64)
	return collector.CollectorHealth{
		Running:     c.running.Load(),
		EventsTotal: c.eventCount.Load(),
		ErrorCount:  c.errorCount.Load(),
		ThrottlePct: throttle,
		LastError:   lastErr,
	}
}
