//go:build darwin

// Package watchdog — macOS implementation using getrusage(RUSAGE_SELF) for
// CPU time and mach_task_basic_info for RSS, all via golang.org/x/sys/unix.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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

// readMemMB returns the peak RSS in megabytes via getrusage(RUSAGE_SELF).
// ru_maxrss is in bytes on macOS (unlike Linux where it is KB).
func (w *Watchdog) readMemMB() (float64, error) {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0, fmt.Errorf("getrusage: %w", err)
	}
	return float64(ru.Maxrss) / (1024 * 1024), nil
}
