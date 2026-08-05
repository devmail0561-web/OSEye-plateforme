package platform_test

// This file verifies that the platform package compiles correctly.
// Interface satisfaction is checked at compile time via mock implementations.

import (
	"context"

	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
)

// mockDriver is a minimal PlatformDriver used only to verify the interface compiles.
type mockDriver struct{}

func (m *mockDriver) Name() string { return "mock" }

func (m *mockDriver) Collectors(_ *config.Config) ([]collector.Collector, error) {
	return nil, nil
}

func (m *mockDriver) Capabilities() platform.PlatformCapabilities {
	return platform.PlatformCapabilities{}
}

// Compile-time assertion: mockDriver satisfies PlatformDriver.
var _ platform.PlatformDriver = (*mockDriver)(nil)

// mockCollector is a minimal Collector used to verify the interface compiles.
type mockCollector struct{}

func (c *mockCollector) Name() string                                        { return "mock" }
func (c *mockCollector) Start(_ context.Context, _ chan<- collector.RawEvent) error { return nil }
func (c *mockCollector) Stop() error                                         { return nil }
func (c *mockCollector) SetThrottle(_ float64)                               {}
func (c *mockCollector) Health() collector.CollectorHealth                   { return collector.CollectorHealth{} }

// Compile-time assertion: mockCollector satisfies Collector.
var _ collector.Collector = (*mockCollector)(nil)
