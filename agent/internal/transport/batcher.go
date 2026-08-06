package transport

import (
	"context"
	"time"

	"github.com/oseye/agent/internal/collector"
)

// Batcher accumulates RawEvents from an input channel and emits batches
// either when the batch reaches maxSize events or when timeout elapses since
// the first event in the current batch.
type Batcher struct {
	maxSize int
	timeout time.Duration
}

// NewBatcher creates a Batcher that flushes when size == maxSize or timeout
// has elapsed since the first event of the current batch.
func NewBatcher(maxSize int, timeout time.Duration) *Batcher {
	if maxSize <= 0 {
		maxSize = 1
	}
	return &Batcher{
		maxSize: maxSize,
		timeout: timeout,
	}
}

// Run reads RawEvents from in, accumulates them into batches, and calls
// sendFn for each complete batch.  It blocks until ctx is cancelled.
//
// sendFn is called synchronously; if it returns an error the batch is
// dropped and Run continues (caller decides how to handle errors at the
// sendFn level, e.g. via retry inside GRPCClient.SendBatch).
//
// The pending batch is flushed on ctx.Done() if non-empty.
func (b *Batcher) Run(ctx context.Context, in <-chan collector.RawEvent, sendFn func([]collector.RawEvent) error) error {
	batch := make([]collector.RawEvent, 0, b.maxSize)
	var timer *time.Timer

	flush := func() {
		if len(batch) == 0 {
			return
		}
		toSend := make([]collector.RawEvent, len(batch))
		copy(toSend, batch)
		batch = batch[:0]
		_ = sendFn(toSend)
	}

	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			// drain the channel so a stale tick can't trigger a double-flush
			select {
			case <-timer.C:
			default:
			}
			timer = nil
		}
	}

	for {
		// Determine whether we have a running timer channel to select on.
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}

		select {
		case <-ctx.Done():
			stopTimer()
			flush()
			return ctx.Err()

		case ev, ok := <-in:
			if !ok {
				// Input channel closed; flush what we have and return.
				stopTimer()
				flush()
				return nil
			}

			// Start the deadline timer on the first event of a new batch.
			if len(batch) == 0 {
				timer = time.NewTimer(b.timeout)
			}
			batch = append(batch, ev)

			if len(batch) >= b.maxSize {
				stopTimer()
				flush()
			}

		case <-timerC:
			timer = nil
			flush()
		}
	}
}
