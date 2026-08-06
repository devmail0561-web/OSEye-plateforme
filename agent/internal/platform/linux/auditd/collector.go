//go:build linux

package auditd

import (
	"context"

	"github.com/oseye/agent/internal/collector"
)

// AuditdCollector is a stub — full libaudit integration is planned for Phase 2.
// It satisfies the Collector interface but emits no events.
type AuditdCollector struct{}

func New() *AuditdCollector { return &AuditdCollector{} }

func (c *AuditdCollector) Name() string { return "auditd" }

// Start blocks until ctx is cancelled. No events are emitted (stub).
func (c *AuditdCollector) Start(ctx context.Context, _ chan<- collector.RawEvent) error {
	<-ctx.Done()
	return nil
}

func (c *AuditdCollector) Stop() error           { return nil }
func (c *AuditdCollector) SetThrottle(_ float64) {}
func (c *AuditdCollector) Health() collector.CollectorHealth {
	return collector.CollectorHealth{Running: false}
}
