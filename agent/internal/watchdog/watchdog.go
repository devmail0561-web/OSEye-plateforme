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

const (
	jiffiesPerSecond = 100 // standard Linux HZ
	emergencyFactor  = 0.1
)

// Watchdog periodically reads the agent's CPU/RAM usage and adjusts the
// collector throttle factor so the agent respects its resource budget.
type Watchdog struct {
	maxCPUPct float64
	maxMemMB  float64
	manager   *collector.CollectorManager
	interval  time.Duration
	pid       int

	prevCPUJiffies uint64
	prevCPUSet     bool
}

// New returns a Watchdog over the given manager with the configured resource
// limits. CPU % and memory MB come from config (MaxCPUPct / MaxMemMB).
func New(maxCPUPct, maxMemMB float64, mgr *collector.CollectorManager) *Watchdog {
	return &Watchdog{
		maxCPUPct: maxCPUPct,
		maxMemMB:  maxMemMB,
		manager:   mgr,
		interval:  5 * time.Second,
		pid:       os.Getpid(),
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
			w.tick(ctx)
		}
	}
}

func (w *Watchdog) tick(ctx context.Context) {
	cpuPct, _ := w.readCPUPercent()
	memMB, _ := w.readMemMB()
	factor := w.computeThrottle(cpuPct, memMB)
	w.manager.SetThrottle(factor)
	slog.Debug("watchdog tick",
		"cpu_pct", cpuPct,
		"mem_mb", memMB,
		"throttle", factor,
	)
}

// computeThrottle derives a throttle factor from the measured CPU% and memory MB.
func (w *Watchdog) computeThrottle(cpuPct, memMB float64) float64 {
	switch {
	case cpuPct < w.maxCPUPct*0.5 && memMB < w.maxMemMB*0.5:
		return 1.0
	case cpuPct > w.maxCPUPct || memMB > w.maxMemMB:
		return emergencyFactor
	default:
		// Between 50% and 100% of the max CPU budget — linear scaling down.
		if w.maxCPUPct > 0 {
			return 1.0 - (cpuPct/w.maxCPUPct)*0.5
		}
		return 1.0
	}
}

// readCPUPercent reads /proc/self/stat (utime, stime) and computes the delta
// since the last call, expressed as a percentage of all cores.
func (w *Watchdog) readCPUPercent() (float64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return 0, nil
	}
	utime, err1 := strconv.ParseUint(fields[13], 10, 64)
	stime, err2 := strconv.ParseUint(fields[14], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, nil
	}

	now := utime + stime
	if !w.prevCPUSet {
		w.prevCPUJiffies = now
		w.prevCPUSet = true
		return 0, nil
	}

	delta := now - w.prevCPUJiffies
	w.prevCPUJiffies = now
	intervalSec := w.interval.Seconds()
	if intervalSec <= 0 {
		intervalSec = 1
	}
	// delta jiffies over one interval → fraction of a single core → ×100 → per-core %.
	corePct := (float64(delta) / jiffiesPerSecond) / intervalSec * 100
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
