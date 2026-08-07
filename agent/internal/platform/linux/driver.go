//go:build linux

package linux

import (
	"log/slog"
	"strconv"

	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/platform"
	"github.com/oseye/agent/internal/platform/linux/auditd"
	"github.com/oseye/agent/internal/platform/linux/ebpf"
	"github.com/oseye/agent/internal/platform/linux/fanotify"
	"github.com/oseye/agent/internal/platform/linux/inotify"
	"github.com/oseye/agent/internal/platform/linux/journald"
	"github.com/oseye/agent/internal/platform/linux/netlink"
	"github.com/oseye/agent/internal/platform/linux/procfs"
	"github.com/oseye/agent/internal/platform/linux/syslog"
	"github.com/oseye/agent/internal/platform/linux/udev"
)

// LinuxDriver is the PlatformDriver implementation for Linux.
type LinuxDriver struct{}

func init() { platform.Register(&LinuxDriver{}) }

func (d *LinuxDriver) Name() string { return "linux" }

func (d *LinuxDriver) Collectors(cfg *config.Config) ([]collector.Collector, error) {
	logger := slog.Default()

	colls := make([]collector.Collector, 0, 9)
	colls = append(colls, procfs.New(), auditd.New(), ebpf.New())

	if f, err := fanotify.NewFanotifyCollector(cfg.FanotifyPaths, logger); err == nil {
		colls = append(colls, f)
	}
	if i, err := inotify.NewInotifyCollector(toInotifyWatches(cfg.InotifyWatches), logger); err == nil {
		colls = append(colls, i)
	}

	if n, err := netlink.NewNetlinkCollector(0, logger); err == nil {
		colls = append(colls, n)
	}

	if j, err := journald.NewJournaldCollector(cfg.JournaldUnits, journaldPriority(cfg.JournaldPriority), logger); err == nil {
		colls = append(colls, j)
	}
	if s, err := syslog.NewSyslogCollector(cfg.SyslogAddr, logger); err == nil {
		colls = append(colls, s)
	}
	if u, err := udev.NewUdevCollector(logger); err == nil {
		colls = append(colls, u)
	}

	return colls, nil
}

// toInotifyWatches converts config.InotifyWatch to the inotify package type.
func toInotifyWatches(cfg []config.InotifyWatch) []inotify.InotifyWatch {
	out := make([]inotify.InotifyWatch, 0, len(cfg))
	for _, w := range cfg {
		out = append(out, inotify.InotifyWatch{
			Path:      w.Path,
			Recursive: w.Recursive,
			Mask:      w.Mask,
		})
	}
	return out
}

// journaldPriority converts the config string to the integer journald priority level.
// An empty or invalid value returns -1 (all priorities).
func journaldPriority(s string) int {
	if s == "" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
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
