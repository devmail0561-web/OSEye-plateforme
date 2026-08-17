//go:build windows

// Package watchdog — Windows implementation using GetProcessTimes +
// GetProcessMemoryInfo to measure CPU% and RSS without CGO.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"golang.org/x/sys/windows"
)

const emergencyFactor = 0.1

// Watchdog monitors CPU and memory usage and throttles collectors accordingly.
type Watchdog struct {
	maxCPUPct float64
	maxMemMB  float64
	manager   *collector.CollectorManager
	interval  time.Duration

	prevKernelTime uint64
	prevUserTime   uint64
	prevWallTime   int64
	prevSet        bool
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

// readCPUPercent uses GetProcessTimes to compute CPU% since last call.
// Returns the fraction of wall-clock time spent in kernel+user mode × 100.
func (w *Watchdog) readCPUPercent() (float64, error) {
	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess: %w", err)
	}

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, fmt.Errorf("GetProcessTimes: %w", err)
	}

	kernelNs := filetimeToNs(kernel)
	userNs := filetimeToNs(user)
	nowNs := time.Now().UnixNano()

	if !w.prevSet {
		w.prevKernelTime = kernelNs
		w.prevUserTime = userNs
		w.prevWallTime = nowNs
		w.prevSet = true
		return 0, nil
	}

	// Guard against counter regression (system reboot, overflow): skip this cycle.
	if kernelNs < w.prevKernelTime || userNs < w.prevUserTime {
		w.prevKernelTime = kernelNs
		w.prevUserTime = userNs
		w.prevWallTime = nowNs
		return 0, nil
	}

	dKernel := float64(kernelNs - w.prevKernelTime)
	dUser := float64(userNs - w.prevUserTime)
	dWall := float64(nowNs - w.prevWallTime)

	w.prevKernelTime = kernelNs
	w.prevUserTime = userNs
	w.prevWallTime = nowNs

	if dWall <= 0 {
		return 0, nil
	}
	return (dKernel + dUser) / dWall * 100.0, nil
}

// PROCESS_MEMORY_COUNTERS mirrors the Windows structure.
type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	modpsapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo    = modpsapi.NewProc("GetProcessMemoryInfo")
)

// readMemMB returns the process Working Set size in megabytes.
func (w *Watchdog) readMemMB() (float64, error) {
	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess: %w", err)
	}
	var pmc processMemoryCounters
	pmc.Cb = uint32(unsafe.Sizeof(pmc))
	r, _, err := procGetProcessMemoryInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.Cb),
	)
	if r == 0 {
		return 0, fmt.Errorf("GetProcessMemoryInfo: %w", err)
	}
	return float64(pmc.WorkingSetSize) / (1024 * 1024), nil
}

// filetimeToNs converts a FILETIME (100-ns intervals since 1601) to nanoseconds.
// Parentheses are required: without them Go precedence gives
//
//	HighDateTime << (32 & (LowDateTime * 100))   ← wrong
//
// The correct formula ORs the two 32-bit halves then multiplies by 100.
func filetimeToNs(ft windows.Filetime) uint64 {
	return (uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)) * 100
}
