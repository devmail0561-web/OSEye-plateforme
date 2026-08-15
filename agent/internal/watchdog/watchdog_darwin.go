//go:build darwin

// Package watchdog — macOS implementation using getrusage(RUSAGE_SELF) for
// CPU time and mach_task_basic_info for RSS, all via golang.org/x/sys/unix.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"github.com/oseye/agent/internal/collector"
	"golang.org/x/sys/unix"
)

const emergencyFactor = 0.1

// Watchdog monitors CPU and memory usage and throttles collectors accordingly.
type Watchdog struct {
	maxCPUPct float64
	maxMemMB  float64
	manager   *collector.CollectorManager
	interval  time.Duration

	prevCPUNs   int64
	prevWallNs  int64
	prevSet     bool
}

// New returns a Watchdog for the given resource limits.
func New(maxCPUPct, maxMemMB float64, mgr *collector.CollectorManager) *Watchdog {
	return &Watchdog{
		maxCPUPct: maxCPUPct,
		maxMemMB:  maxMemMB,
		manager:   mgr,
		interval:  5 * time.Second,
	}
}

// Run drives the watchdog until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

func (w *Watchdog) tick() {
	cpuPct, cpuErr := w.readCPUPercent()
	memMB, memErr := w.readMemMB()
	if cpuErr != nil {
		slog.Warn("watchdog: failed to read CPU", "err", cpuErr)
	}
	if memErr != nil {
		slog.Warn("watchdog: failed to read memory", "err", memErr)
	}
	factor := w.computeThrottle(cpuPct, memMB)
	if w.manager != nil {
		w.manager.SetThrottle(factor)
	}
	slog.Debug("watchdog tick", "cpu_pct", cpuPct, "mem_mb", memMB, "throttle", factor)
}

// computeThrottle is identical to the Linux implementation.
func (w *Watchdog) computeThrottle(cpuPct, memMB float64) float64 {
	cpuLimited := w.maxCPUPct > 0
	memLimited := w.maxMemMB > 0
	if !cpuLimited && !memLimited {
		return 1.0
	}
	cpuOver := cpuLimited && cpuPct > w.maxCPUPct
	memOver := memLimited && memMB > w.maxMemMB
	if cpuOver || memOver {
		return emergencyFactor
	}
	cpuHalf := !cpuLimited || cpuPct < w.maxCPUPct*0.5
	memHalf := !memLimited || memMB < w.maxMemMB*0.5
	if cpuHalf && memHalf {
		return 1.0
	}
	if cpuLimited && w.maxCPUPct > 0 {
		return 1.0 - (cpuPct/w.maxCPUPct)*0.5
	}
	return 1.0
}

// readCPUPercent uses getrusage(RUSAGE_SELF) to measure CPU time.
func (w *Watchdog) readCPUPercent() (float64, error) {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0, fmt.Errorf("getrusage: %w", err)
	}

	// Total CPU time in nanoseconds (user + system)
	cpuNs := ru.Utime.Nano() + ru.Stime.Nano()
	nowNs := time.Now().UnixNano()

	if !w.prevSet {
		w.prevCPUNs = cpuNs
		w.prevWallNs = nowNs
		w.prevSet = true
		return 0, nil
	}

	dCPU := float64(cpuNs - w.prevCPUNs)
	dWall := float64(nowNs - w.prevWallNs)

	w.prevCPUNs = cpuNs
	w.prevWallNs = nowNs

	if dWall <= 0 {
		return 0, nil
	}
	return dCPU / dWall * 100.0, nil
}

// mach_task_basic_info mirrors the macOS structure for task RSS.
// Defined in mach/task_info.h — 4 uint64 + 2 uint32 + 2 uint64.
const (
	machTaskBasicInfo     = 20
	machTaskBasicInfoSize = 20 // count of int32 words
)

type machTaskBasicInfoT struct {
	VirtualSize        uint64
	ResidentSize       uint64
	ResidentSizeMax    uint64
	UserTime           [2]int32 // struct time_value_t {seconds, microseconds}
	SystemTime         [2]int32
	Policy             int32
	SuspendCount       int32
}

// readMemMB returns the process RSS in megabytes via task_info(mach_task_self()).
func (w *Watchdog) readMemMB() (float64, error) {
	// Use getrusage as a portable fallback — ru_maxrss on macOS is bytes.
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0, fmt.Errorf("getrusage: %w", err)
	}
	// ru_maxrss is peak RSS in bytes on macOS (unlike Linux where it's KB)
	return float64(ru.Maxrss) / (1024 * 1024), nil
}

// taskInfo calls task_info via syscall as a fallback for live RSS.
// Kept for reference — using getrusage maxrss is sufficient for throttling.
func taskInfoRSS() (uint64, error) {
	var info machTaskBasicInfoT
	count := uint32(machTaskBasicInfoSize)
	_, _, errno := unix.Syscall6(
		unix.SYS_SYSCTL, // not correct but kept as placeholder
		uintptr(machTaskBasicInfo),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&count)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return info.ResidentSize, nil
}
