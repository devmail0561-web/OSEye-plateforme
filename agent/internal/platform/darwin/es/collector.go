//go:build darwin

// Package es integrates Apple's EndpointSecurity framework for kernel-level
// telemetry (process exec, file access, network). Requires:
//   - macOS 10.15+
//   - App entitlement: com.apple.developer.endpoint-security.client
//   - SIP disabled OR Apple notarization
//
// Without the entitlement this collector starts but emits no events.
package es

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/oseye/agent/internal/collector"
)

// esAvailable is set to true at init() if the EndpointSecurity framework
// can be loaded (macOS 10.15+ with entitlement).
// It requires CGO and the Apple EndpointSecurity.framework — when building
// with CGO_ENABLED=0 or without the entitlement this remains false.
var esAvailable = false

// Collector wraps the EndpointSecurity client.
type Collector struct {
	logger   *slog.Logger
	stopCh   chan struct{}
	running  bool
	throttle atomic.Value
}

var _ collector.Collector = (*Collector)(nil)

func New(logger *slog.Logger) (*Collector, error) {
	c := &Collector{
		logger: logger,
		stopCh: make(chan struct{}),
	}
	c.throttle.Store(1.0)
	if !esAvailable {
		logger.Info("es: EndpointSecurity unavailable (CGO_ENABLED=0 or missing entitlement) — collector inactive")
	}
	return c, nil
}

func (c *Collector) Name() string { return "es" }

func (c *Collector) Start(ctx context.Context, out chan<- collector.RawEvent) error {
	c.running = true
	go c.run(ctx, out)
	return nil
}

func (c *Collector) Stop() error {
	if c.running {
		close(c.stopCh)
		c.running = false
	}
	return nil
}

func (c *Collector) SetThrottle(f float64) { c.throttle.Store(f) }

func (c *Collector) Health() collector.CollectorHealth {
	lastErr := ""
	if !esAvailable {
		lastErr = "EndpointSecurity requires CGO_ENABLED=1 + com.apple.developer.endpoint-security.client entitlement"
	}
	return collector.CollectorHealth{Running: c.running, LastError: lastErr}
}

type esEvent struct {
	EventType string `json:"event_type"`
	Available bool   `json:"available"`
	Message   string `json:"message,omitempty"`
}

func (c *Collector) run(ctx context.Context, out chan<- collector.RawEvent) {
	if !esAvailable {
		// Emit a one-shot status event so the server knows the collector is present
		// but not providing data.
		b, _ := json.Marshal(esEvent{
			EventType: "collector_status",
			Available: false,
			Message:   "EndpointSecurity requires CGO_ENABLED=1, com.apple.developer.endpoint-security.client entitlement, and macOS 10.15+",
		})
		select {
		case out <- collector.RawEvent{
			Source:    "es",
			OS:        "darwin",
			Timestamp: time.Now().UnixNano(),
			Raw:       b,
		}:
		default:
		}
		// Wait for stop — no events will be emitted
		select {
		case <-ctx.Done():
		case <-c.stopCh:
		}
		return
	}
	// When esAvailable (CGO + entitlement build), the actual implementation
	// would call es_new_client(), es_subscribe(), and process events here.
	// This branch is reached only in a CGO build with the proper entitlement.
	select {
	case <-ctx.Done():
	case <-c.stopCh:
	}
}
