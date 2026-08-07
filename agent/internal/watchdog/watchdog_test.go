//go:build linux

package watchdog

import (
	"context"
	"sync"
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
		{"medium", 3.0, 100.0, 1.0 - 3.0/4.0*0.5}, // 50–100% of max → scaling
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

func TestWatchdogZeroLimitsDisabledWatchdog(t *testing.T) {
	// H3 fix: maxCPUPct==0 and maxMemMB==0 must return 1.0, not emergency.
	mgr := collector.NewManager(nil, 4)
	w := New(0, 0, mgr)

	// Even with non-zero CPU/RAM readings, full throttle must be returned.
	for _, c := range []struct{ cp, mem float64 }{
		{0.0, 0.0},
		{5.0, 300.0}, // values that would trigger emergency with non-zero limits
		{1.0, 50.0},
	} {
		if got := w.computeThrottle(c.cp, c.mem); got != 1.0 {
			t.Errorf("zero limits: computeThrottle(%v,%v) = %v, want 1.0", c.cp, c.mem, got)
		}
	}
}

func TestWatchdogOnlyMemLimitSet(t *testing.T) {
	// H3 fix: only memMB limit set — CPU should not trigger emergency.
	w := New(0, 256.0, nil)

	if got := w.computeThrottle(99.9, 100.0); got != 1.0 {
		t.Errorf("high CPU with no CPU limit: got %v, want 1.0", got)
	}
	if got := w.computeThrottle(0, 300.0); got != emergencyFactor {
		t.Errorf("high mem over limit: got %v, want %v", got, emergencyFactor)
	}
}

func TestWatchdogClampsThrottleViaManager(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	// manager with no collectors must not panic on any factor
	mgr.SetThrottle(-1)
	mgr.SetThrottle(2.5)
	mgr.SetThrottle(0.5)
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
	if _, err := w.readCPUPercent(); err != nil {
		t.Fatalf("initial readCPUPercent error = %v", err)
	}
	if _, err := w.readCPUPercent(); err != nil {
		t.Fatalf("second readCPUPercent error = %v", err)
	}
}

func TestWatchdogRunContextCancellation(t *testing.T) {
	// M13 fix: use a WaitGroup instead of time.Sleep to avoid racy test.
	mgr := collector.NewManager(nil, 4)
	w := New(4, 256, mgr)
	// Shorten the interval so the ticker fires quickly in the test.
	w.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Run(ctx)
	}()

	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		// OK — goroutine exited promptly
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog.Run did not exit within 2s after context cancellation")
	}
}
