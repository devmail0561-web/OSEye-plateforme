//go:build linux

package linux

import (
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
	"github.com/oseye/agent/internal/platform/linux/auditd"
	"github.com/oseye/agent/internal/platform/linux/procfs"
)

// LinuxDriver is the PlatformDriver implementation for Linux.
type LinuxDriver struct{}

func init() { platform.Register(&LinuxDriver{}) }

func (d *LinuxDriver) Name() string { return "linux" }

func (d *LinuxDriver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
	return []collector.Collector{
		procfs.New(),
		auditd.New(),
	}, nil
}

func (d *LinuxDriver) Capabilities() platform.PlatformCapabilities {
	return platform.PlatformCapabilities{
		HasKernelTracing:  true,
		HasFileAudit:      true,
		HasNetworkAudit:   true,
		HasContainerAware: true,
		MaxCollectors:     9,
	}
}
