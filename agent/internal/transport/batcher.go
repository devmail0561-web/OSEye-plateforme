package transport

import (
	"context"
	"log/slog"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
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
const maxBatchCap = 10000

func NewBatcher(maxSize int, timeout time.Duration) *Batcher {
	if maxSize <= 0 {
		maxSize = 1
	}
	if maxSize > maxBatchCap {
		maxSize = maxBatchCap
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

	// Timer is created once and reused via Reset to avoid per-batch allocations.
	timer := time.NewTimer(b.timeout)
	if !timer.Stop() {
		<-timer.C
	}
	var timerC <-chan time.Time // nil when timer is not active

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Handoff: pass ownership of the slice to sendFn, allocate a fresh one.
		toSend := batch
		batch = make([]collector.RawEvent, 0, b.maxSize)
		if err := sendFn(toSend); err != nil {
			slog.Error("batcher: failed to send batch, events lost", "count", len(toSend), "err", err)
			// TODO: persist to SQLite buffer for retry
		}
	}

	stopTimer := func() {
		if timerC != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timerC = nil
		}
	}

	for {
		select {
		case <-ctx.Done():
			stopTimer()
			flush()
			return ctx.Err()

		case ev, ok := <-in:
			if !ok {
				stopTimer()
				flush()
				return nil
			}

			// Start the deadline timer on the first event of a new batch.
			if len(batch) == 0 {
				timer.Reset(b.timeout)
				timerC = timer.C
			}
			batch = append(batch, ev)

			if len(batch) >= b.maxSize {
				stopTimer()
				flush()
			}

		case <-timerC:
			timerC = nil
			flush()
		}
	}
}
