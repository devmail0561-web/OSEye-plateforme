package transport

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/oseye/agent/internal/collector"
)

// makeEvent returns a minimal RawEvent for testing.
func makeEvent(src string) collector.RawEvent {
	return collector.RawEvent{
		Source:    src,
		OS:        "linux",
		Timestamp: time.Now().UnixNano(),
		Raw:       []byte("test"),
	}
}

// TestBatcherFlushBySize verifies that a batch is flushed when exactly
// maxSize events have been accumulated.
func TestBatcherFlushBySize(t *testing.T) {
	t.Parallel()

	const maxSize = 5
	b := NewBatcher(maxSize, 10*time.Second) // very long timeout — must flush by size

	in := make(chan collector.RawEvent, maxSize*2)
	var mu sync.Mutex
	var batches [][]collector.RawEvent

	sendFn := func(evs []collector.RawEvent) error {
		mu.Lock()
		batches = append(batches, evs)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send exactly maxSize events, then close the channel.
	for i := 0; i < maxSize; i++ {
		in <- makeEvent("test")
	}
	close(in)

	if err := b.Run(ctx, in, sendFn); err != nil && err != context.Canceled {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	mu.Lock()
	got := len(batches)
	mu.Unlock()

	if got != 1 {
		t.Fatalf("expected 1 batch, got %d", got)
	}
	if len(batches[0]) != maxSize {
		t.Fatalf("expected batch size %d, got %d", maxSize, len(batches[0]))
	}
}

// TestBatcherFlushByTimeout verifies that a partial batch is flushed after
// the timeout expires even when maxSize has not been reached.
func TestBatcherFlushByTimeout(t *testing.T) {
	t.Parallel()

	const maxSize = 100
	const flushTimeout = 50 * time.Millisecond
	b := NewBatcher(maxSize, flushTimeout)

	in := make(chan collector.RawEvent, 10)
	flushed := make(chan []collector.RawEvent, 10)

	sendFn := func(evs []collector.RawEvent) error {
		cp := make([]collector.RawEvent, len(evs))
		copy(cp, evs)
		flushed <- cp
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = b.Run(ctx, in, sendFn)
	}()

	// Send fewer events than maxSize.
	in <- makeEvent("a")
	in <- makeEvent("b")
	in <- makeEvent("c")

	// Wait for the timeout flush.
	select {
	case batch := <-flushed:
		if len(batch) != 3 {
			t.Errorf("expected 3 events in timeout-flushed batch, got %d", len(batch))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: batch was not flushed after timeout expired")
	}
}

// TestBatcherCtxDone verifies that Run flushes the pending batch and returns
// when the context is cancelled.
func TestBatcherCtxDone(t *testing.T) {
	t.Parallel()

	b := NewBatcher(100, 10*time.Second)

	in := make(chan collector.RawEvent, 10)
	var mu sync.Mutex
	var received []collector.RawEvent

	sendFn := func(evs []collector.RawEvent) error {
		mu.Lock()
		received = append(received, evs...)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- b.Run(ctx, in, sendFn)
	}()

	// Push a few events then cancel the context.
	in <- makeEvent("x")
	in <- makeEvent("y")
	time.Sleep(10 * time.Millisecond) // let Run read them
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout: Run did not return after ctx cancel")
	}

	mu.Lock()
	n := len(received)
	mu.Unlock()

	if n != 2 {
		t.Errorf("expected 2 flushed events on cancel, got %d", n)
	}
}

// TestBatcherMultipleBatches verifies that N*maxSize events produce N batches.
func TestBatcherMultipleBatches(t *testing.T) {
	t.Parallel()

	const maxSize = 4
	const numBatches = 3
	b := NewBatcher(maxSize, 10*time.Second)

	in := make(chan collector.RawEvent, maxSize*numBatches+1)
	var mu sync.Mutex
	var batches [][]collector.RawEvent

	sendFn := func(evs []collector.RawEvent) error {
		cp := make([]collector.RawEvent, len(evs))
		copy(cp, evs)
		mu.Lock()
		batches = append(batches, cp)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := 0; i < maxSize*numBatches; i++ {
		in <- makeEvent("multi")
	}
	close(in)

	if err := b.Run(ctx, in, sendFn); err != nil && err != context.Canceled {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	mu.Lock()
	got := len(batches)
	mu.Unlock()

	if got != numBatches {
		t.Fatalf("expected %d batches, got %d", numBatches, got)
	}
	for i, batch := range batches {
		if len(batch) != maxSize {
			t.Errorf("batch %d: expected size %d, got %d", i, maxSize, len(batch))
		}
	}
}
