//go:build linux

package responder

import (
	"context"
	"io"
	"log/slog"
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
}

// NewReporter creates a Reporter with an internal buffer of capacity cap.
func NewReporter(svc gen.AgentServiceClient, cap int) *Reporter {
	return &Reporter{
		svc:     svc,
		reports: make(chan *gen.ActionReport, cap),
	}
}

// Send enqueues an ActionReport for delivery. Non-blocking — drops if full and logs.
func (r *Reporter) Send(commandID, status, errMsg string) {
	report := &gen.ActionReport{
		CommandId:     commandID,
		Status:        status,
		Error:         errMsg,
		ExecutedAtNs:  time.Now().UnixNano(),
	}
	select {
	case r.reports <- report:
	default:
		slog.Warn("reporter: channel full, dropping report", "command_id", commandID)
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
				select {
				case r.reports <- report:
				default:
				}
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

// Close the internal channel.
func (r *Reporter) Close() { close(r.reports) }

// MustSend is a helper for the Recv-less EOF path in ReportActions.
func ioEOF(err error) bool { return err == io.EOF }
