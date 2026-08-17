//go:build linux

// Package procfs — benchmarks for delta scan performance.
// Run with: go test -bench=. -benchmem -benchtime=5s ./internal/platform/linux/procfs/
package procfs

import (
	"context"
	"testing"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

// BenchmarkScan_Initial measures the cost of the first scan (full snapshot of all
// live processes). This runs once at agent startup.
func BenchmarkScan_Initial(b *testing.B) {
	c := New()
	out := make(chan collector.RawEvent, 4096)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prevPIDs, _ := c.scan(ctx, out, nil, false)
		// Drain emitted events to avoid blocking the channel.
		for len(out) > 0 {
			<-out
		}
		_ = prevPIDs
	}
}

// BenchmarkScan_StableState measures the steady-state delta scan where no processes
// have appeared or disappeared. This is the dominant case in production.
func BenchmarkScan_StableState(b *testing.B) {
	c := New()
	out := make(chan collector.RawEvent, 4096)
	ctx := context.Background()

	// Warm up: get initial PID set.
	prevPIDs, _ := c.scan(ctx, out, nil, false)
	for len(out) > 0 {
		<-out
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		current, _ := c.scan(ctx, out, prevPIDs, true)
		for len(out) > 0 {
			<-out
		}
		prevPIDs = current
	}
}

// BenchmarkScan_ReportBytes reports bytes-per-scan for throughput analysis.
func BenchmarkScan_ReportBytes(b *testing.B) {
	c := New()
	out := make(chan collector.RawEvent, 4096)
	ctx := context.Background()

	// One initial scan to measure total raw bytes emitted.
	prevPIDs, _ := c.scan(ctx, out, nil, false)
	var totalBytes int64
	for len(out) > 0 {
		ev := <-out
		totalBytes += int64(len(ev.Raw))
	}
	if totalBytes > 0 {
		b.SetBytes(totalBytes)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		current, _ := c.scan(ctx, out, prevPIDs, true)
		for len(out) > 0 {
			<-out
		}
		prevPIDs = current
	}
}
