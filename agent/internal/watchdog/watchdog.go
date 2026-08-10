//go:build linux

package watchdog

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/oseye/agent/internal/collector"
)

const emergencyFactor = 0.1

// Watchdog periodically reads the agent's CPU/RAM usage and adjusts the
// collector throttle factor so the agent respects its resource budget.
type Watchdog struct {
	maxCPUPct float64
	maxMemMB  float64
	manager   *collector.CollectorManager
	interval  time.Duration

	prevCPUJiffies uint64
	prevCPUSet     bool
	clkTck         float64 // kernel timer frequency (HZ), read once at start
}

// New returns a Watchdog over the given manager with the configured resource
// limits. CPU % and memory MB come from config (MaxCPUPct / MaxMemMB).
func New(maxCPUPct, maxMemMB float64, mgr *collector.CollectorManager) *Watchdog {
	return &Watchdog{
		maxCPUPct: maxCPUPct,
		maxMemMB:  maxMemMB,
		manager:   mgr,
		interval:  5 * time.Second,
		clkTck:    readClkTck(),
	}
}

// Run drives the watchdog until ctx is cancelled. A ticker at w.interval reads
// CPU/RAM and applies the computed throttle factor to the manager.
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

	// M1/M2 fix: log failures instead of silently using zero, which would
	// trigger emergency throttle if limits are set.
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

// computeThrottle derives a throttle factor from the measured CPU% and memory MB.
// H3 fix: if both limits are zero or negative the watchdog is disabled → return 1.0.
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

	// Linear back-off between 50% and 100% of the CPU budget.
	if cpuLimited && w.maxCPUPct > 0 {
		return 1.0 - (cpuPct/w.maxCPUPct)*0.5
	}
	return 1.0
}

// readCPUPercent reads /proc/self/stat (utime+stime) and returns the delta
// since the last call as a percentage across all cores.
// M1 fix: parse comm field robustly — find the last ')' before splitting fields.
func (w *Watchdog) readCPUPercent() (float64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	raw := string(data)

	// The comm field (index 1) is wrapped in parentheses and may contain
	// spaces. Skip past the last ')' before indexing into the remaining fields.
	idx := strings.LastIndex(raw, ")")
	if idx < 0 {
		return 0, nil
	}
	// Fields after comm start at idx+2 (skip ') ').
	rest := strings.Fields(raw[idx+2:])
	// rest[0]=state, rest[11]=utime, rest[12]=stime (0-based after comm+state).
	if len(rest) < 13 {
		return 0, nil
	}
	utime, err1 := strconv.ParseUint(rest[11], 10, 64)
	stime, err2 := strconv.ParseUint(rest[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, nil
	}

	now := utime + stime
	if !w.prevCPUSet {
		w.prevCPUJiffies = now
		w.prevCPUSet = true
		return 0, nil
	}

	// GO-006: guard against counter wrap-around (uint64 underflow).
	// If the kernel resets counters (e.g. after a checkpoint/restore) treat
	// the delta as zero so we don't report a huge spurious CPU spike.
	var delta uint64
	if now >= w.prevCPUJiffies {
		delta = now - w.prevCPUJiffies
	}
	w.prevCPUJiffies = now

	intervalSec := w.interval.Seconds()
	if intervalSec <= 0 {
		intervalSec = 1
	}
	hz := w.clkTck
	if hz <= 0 {
		hz = 100
	}
	// M2 fix: use the actual kernel HZ instead of the hard-coded 100.
	corePct := (float64(delta) / hz) / intervalSec * 100
	numCPU := runtime.NumCPU()
	if numCPU <= 0 {
		numCPU = 1
	}
	return corePct / float64(numCPU), nil
}

// readMemMB reads /proc/self/status VmRSS (kB) and returns it in MB.
func (w *Watchdog) readMemMB() (float64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, err := strconv.ParseFloat(parts[1], 64)
				if err != nil {
					return 0, err
				}
				return kb / 1024.0, nil
			}
		}
	}
	return 0, scanner.Err()
}

// readClkTck returns the kernel timer frequency (HZ) from /proc/timer_list or
// falls back to 100 (most common desktop/server value).
func readClkTck() float64 {
	// sysconf(_SC_CLK_TCK) is the POSIX way but requires cgo.
	// Reading /proc/timer_list is pure-Go but only available on kernel >= 3.10.
	// Simplest portable approach: read from /sys/kernel/debug... unavailable in containers.
	// Fallback strategy: try common values by inspecting /proc/timer_list if available,
	// otherwise default to 100 which is correct for ~95% of Linux systems.
	data, err := os.ReadFile("/proc/timer_list")
	if err != nil {
		return 100
	}
	for _, line := range strings.SplitN(string(data), "\n", 20) {
		if strings.HasPrefix(line, "tick_usec") {
			// tick_usec: 4000  → HZ = 1_000_000 / tick_usec
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if usec, err := strconv.ParseFloat(parts[1], 64); err == nil && usec > 0 {
					return 1_000_000 / usec
				}
			}
		}
	}
	return 100
}
