//go:build linux

package responder

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/backoff"
)

// Reporter streams ActionReport messages to the server via the ReportActions RPC.
// CIA — Disponibilité : reports are buffered in a channel and retried with
// full-jitter backoff if the connection is lost.
type Reporter struct {
	svc     gen.AgentServiceClient
	reports chan *gen.ActionReport
	// G-R-03: closed (fast path) + once guard prevent double-close and
	// send-on-closed-channel panics when Send() races with Close().
	closed atomic.Bool
	once   sync.Once
}

// NewReporter creates a Reporter with an internal buffer of capacity cap.
// TODO(rate-limiting): Add per-source rate limiting (e.g. golang.org/x/time/rate)
// to prevent a single command source from saturating the reports channel and
// starving other sources. A token-bucket keyed on commandID source is recommended.
func NewReporter(svc gen.AgentServiceClient, cap int) *Reporter {
	return &Reporter{
		svc:     svc,
		reports: make(chan *gen.ActionReport, cap),
	}
}

// safeSend sends v on ch (blocking) and returns true, or returns false without
// panicking if ch is closed. Protects against the TOCTOU race between a
// closed-flag check and the actual channel send.
func safeSend[T any](ch chan<- T, v T) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	ch <- v
	return true
}

// safeSendNonBlocking attempts a non-blocking send on ch. Returns true on
// success, or false if ch is full or closed — without panicking.
func safeSendNonBlocking[T any](ch chan<- T, v T) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}

// Send enqueues an ActionReport for delivery. Non-blocking — drops if full or if
// the reporter has been closed, and logs a warning in both cases.
// G-R-03: closed.Load() is a fast-path early exit; safeSendNonBlocking handles
// the residual TOCTOU window between that check and the channel send, catching
// the send-on-closed-channel panic via recover().
// G-R-01: explicit slog.Warn on every dropped report so operators can detect loss.
func (r *Reporter) Send(commandID, status, errMsg string) {
	if r.closed.Load() {
		slog.Warn("reporter: closed, dropping report", "command_id", commandID)
		return
	}
	report := &gen.ActionReport{
		CommandId:    commandID,
		Status:       status,
		Error:        errMsg,
		ExecutedAtNs: time.Now().UnixNano(),
	}
	if !safeSendNonBlocking(r.reports, report) {
		slog.Warn("reporter: channel full or closed, dropping report", "command_id", commandID)
	}
}

// Run streams pending reports to the server, reconnecting with full-jitter backoff.
func (r *Reporter) Run(ctx context.Context) {
	delay := 1 * time.Second
	const maxDelay = 30 * time.Second

	for {
		err := r.runStream(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("reporter: stream error, reconnecting", "err", err, "delay", delay)
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			delay = backoff.Next(delay, maxDelay)
		}
	}
}

func (r *Reporter) runStream(ctx context.Context) error {
	stream, err := r.svc.ReportActions(ctx)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return nil
		case report, ok := <-r.reports:
			if !ok {
				_, _ = stream.CloseAndRecv()
				return nil
			}
			if err := stream.Send(report); err != nil {
				// Re-enqueue for next connection attempt.
				// safeSendNonBlocking guards against the closed-channel race.
				safeSendNonBlocking(r.reports, report)
				return err
			}
		}
	}
}

// DrainOnShutdown flushes remaining reports with a deadline.
func (r *Reporter) DrainOnShutdown(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = r.runStream(ctx)
}

// Close marks the reporter as closed and closes the internal channel exactly once.
// G-R-03: closed flag is set before the channel close so concurrent Send() calls
// take the fast-path early exit; sync.Once ensures the channel is never closed
// twice (double-close panic) even if Close() is called concurrently or repeatedly.
func (r *Reporter) Close() {
	r.closed.Store(true)
	r.once.Do(func() { close(r.reports) })
}
