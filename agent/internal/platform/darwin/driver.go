//go:build darwin

package darwin

import (
	"log/slog"

	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
	"github.com/oseye/agent/internal/platform/darwin/darwinnet"
	"github.com/oseye/agent/internal/platform/darwin/es"
	"github.com/oseye/agent/internal/platform/darwin/kqueue"
	"github.com/oseye/agent/internal/platform/darwin/ps"
	"github.com/oseye/agent/internal/platform/darwin/unifiedlog"
)

// DarwinDriver is the PlatformDriver implementation for macOS.
type DarwinDriver struct{}

func init() { platform.Register(&DarwinDriver{}) }

func (d *DarwinDriver) Name() string { return "darwin" }

func (d *DarwinDriver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
	logger := slog.Default()
	colls := make([]collector.Collector, 0, 5)

	// Process monitoring via sysctl(kern.proc.all)
	colls = append(colls, ps.New())

	// EndpointSecurity (requires SIP disabled or Apple notarisation + entitlement)
	if e, err := es.New(logger); err == nil {
		colls = append(colls, e)
	}

	// File system watching via kqueue
	if k, err := kqueue.New(cfg.FanotifyPaths, logger); err == nil {
		colls = append(colls, k)
	}

	// Apple Unified Log (replaces syslog on macOS 10.12+)
	if u, err := unifiedlog.New(logger); err == nil {
		colls = append(colls, u)
	}

	// Network connections via netstat
	if n, err := darwinnet.New(logger); err == nil {
		colls = append(colls, n)
	}

	return colls, nil
}

func (d *DarwinDriver) Capabilities() platform.PlatformCapabilities {
	return platform.PlatformCapabilities{
		HasKernelTracing:  true, // EndpointSecurity when entitled
		HasFileAudit:      true,
		HasNetworkAudit:   true,
		HasContainerAware: false,
		MaxCollectors:     5,
	}
}
