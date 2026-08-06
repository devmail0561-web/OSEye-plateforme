package collector

import "context"

// Collector is the OS-agnostic interface implemented by every event source.
type Collector interface {
	// Name returns the collector identifier (e.g. "ebpf", "auditd", "procfs").
	Name() string

	// Start begins event collection, sending RawEvents to out.
	// Blocks until ctx is cancelled or a fatal error occurs.
	Start(ctx context.Context, out chan<- RawEvent) error

	// Stop signals the collector to stop and release resources.
	// Safe to call multiple times.
	Stop() error

	// SetThrottle adjusts the collection rate: 0.0 = paused, 1.0 = full speed.
	SetThrottle(factor float64)

	// Health returns the current operational status of this collector.
	Health() CollectorHealth
}

// RawEvent is the unprocessed output of a collector.
// The payload format is collector-specific; the normalizer handles parsing.
type RawEvent struct {
	Source    string // collector name: "ebpf", "auditd", "procfs", ...
	OS        string // "linux" | "windows" | "darwin"
	Timestamp int64  // nanosecond monotonic clock
	Raw       []byte // raw payload (JSON or binary depending on collector)
}

// CollectorHealth reports the operational state of a collector.
type CollectorHealth struct {
	Running     bool
	ErrorCount  int64
	EventsTotal int64
	ThrottlePct float64
	LastError   string
}
