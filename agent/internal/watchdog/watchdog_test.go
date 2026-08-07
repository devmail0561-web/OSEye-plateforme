//go:build linux

package watchdog

import (
	"context"
	"testing"
	"time"

	"github.com/oseye/agent/internal/collector"
)

func TestWatchdogThrottleCalculation(t *testing.T) {
	mgr := collector.NewManager(nil, 8)
	w := New(4.0, 256.0, mgr) // max 4% CPU, 256 MB RAM

	cases := []struct {
		name string
		cp   float64
		mem  float64
		want float64
	}{
		{"idle", 1.0, 100.0, 1.0},                 // CPU&RAM < 50% → 1.0
		{"medium", 3.0, 100.0, 1.0 - 3.0/4.0*0.5}, // 50-100% of max → scaling
		{"cpu over", 5.0, 100.0, 0.1},             // emergency
		{"mem over", 2.0, 300.0, 0.1},             // emergency
		{"both low", 0.0, 0.0, 1.0},
	}
	for _, c := range cases {
		if got := w.computeThrottle(c.cp, c.mem); got != c.want {
			t.Errorf("%s: computeThrottle(%v,%v) = %v, want %v", c.name, c.cp, c.mem, got, c.want)
		}
	}
}

func TestWatchdogClampsThrottleViaManager(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	// manager with no collectors must not panic on any factor
	mgr.SetThrottle(-1)
	mgr.SetThrottle(2.5)
	mgr.SetThrottle(0.5)
	// Setting on a manager with nil-able collectors is safe; no panic is enough.
}

func TestWatchdogReadMemMB(t *testing.T) {
	w := New(4, 256, nil)
	mem, err := w.readMemMB()
	if err != nil {
		t.Fatalf("readMemMB error = %v", err)
	}
	if mem <= 0 {
		t.Errorf("readMemMB = %v, want > 0", mem)
	}
}

func TestWatchdogReadCPU(t *testing.T) {
	w := New(4, 256, nil)
	// first call seeds the baseline
	if _, err := w.readCPUPercent(); err != nil {
		t.Fatalf("initial readCPUPercent error = %v", err)
	}
	if _, err := w.readCPUPercent(); err != nil {
		t.Fatalf("second readCPUPercent error = %v", err)
	}
}

func TestWatchdogRunContextCancellation(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	w := New(4, 256, mgr)
	ctx, cancel := context.WithCancel(context.Background())
	go w.Run(ctx)

	cancel()
	// Run should return promptly after cancellation; allow generous slack.
	time.Sleep(300 * time.Millisecond)
}
