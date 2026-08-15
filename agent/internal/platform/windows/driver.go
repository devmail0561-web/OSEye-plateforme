//go:build windows

package windows

import (
	"log/slog"

	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
	"github.com/oseye/agent/internal/platform/windows/eventlog"
	"github.com/oseye/agent/internal/platform/windows/etw"
	"github.com/oseye/agent/internal/platform/windows/fswatch"
	"github.com/oseye/agent/internal/platform/windows/registry"
	"github.com/oseye/agent/internal/platform/windows/toolhelp32"
	"github.com/oseye/agent/internal/platform/windows/winnetstat"
)

// WindowsDriver is the PlatformDriver implementation for Windows.
type WindowsDriver struct{}

func init() { platform.Register(&WindowsDriver{}) }

func (d *WindowsDriver) Name() string { return "windows" }

func (d *WindowsDriver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
	logger := slog.Default()
	colls := make([]collector.Collector, 0, 6)

	// Process snapshot via Toolhelp32 API
	colls = append(colls, toolhelp32.New())

	// ETW kernel tracing (process/file/network events)
	colls = append(colls, etw.New())

	// File system watching via ReadDirectoryChangesW
	if f, err := fswatch.New(cfg.FanotifyPaths, logger); err == nil {
		colls = append(colls, f)
	}

	// Windows Registry monitoring
	if r, err := registry.New(logger); err == nil {
		colls = append(colls, r)
	}

	// Windows Event Log (Security, System, Application)
	if e, err := eventlog.New(logger); err == nil {
		colls = append(colls, e)
	}

	// Network connections via netstat
	if n, err := winnetstat.New(logger); err == nil {
		colls = append(colls, n)
	}

	return colls, nil
}

func (d *WindowsDriver) Capabilities() platform.PlatformCapabilities {
	return platform.PlatformCapabilities{
		HasKernelTracing:  true,
		HasFileAudit:      true,
		HasNetworkAudit:   true,
		HasRegistryAudit:  true,
		HasContainerAware: false,
		MaxCollectors:     6,
	}
}
