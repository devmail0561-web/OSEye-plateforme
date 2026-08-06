package platform

import (
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
)

// PlatformDriver is the OS-specific entry point.
// Each OS implements this interface in its own sub-package, registered via init().
type PlatformDriver interface {
	// Name returns the platform identifier, matching runtime.GOOS.
	Name() string

	// Collectors instantiates and returns all collectors available on this platform.
	// CollectorManager only knows this list — not the concrete types.
	Collectors(cfg *config.Config) ([]collector.Collector, error)

	// Capabilities describes what this driver can do (used by SurveillanceProfile).
	Capabilities() PlatformCapabilities
}

// PlatformCapabilities describes the observability capabilities of a platform driver.
type PlatformCapabilities struct {
	HasKernelTracing  bool // eBPF (Linux), ETW (Windows), EndpointSecurity (macOS)
	HasFileAudit      bool
	HasNetworkAudit   bool
	HasRegistryAudit  bool // Windows only
	HasContainerAware bool // reads namespaces/cgroups
	MaxCollectors     int
}
