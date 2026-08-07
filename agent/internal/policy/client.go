//go:build linux

package policy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	gen "github.com/oseye/agent/gen"
)

// PolicyClient maintains the server→agent SurveillanceProfile stream and
// applies profile updates via onProfile serially (ordered, non-racy).
type PolicyClient struct {
	svc       gen.AgentServiceClient
	agentID   []byte
	onProfile func(*gen.SurveillanceProfilePB)
}

// NewClient returns a PolicyClient that opens a ReceivePolicy stream.
func NewClient(svc gen.AgentServiceClient, agentID []byte, onProfile func(*gen.SurveillanceProfilePB)) *PolicyClient {
	return &PolicyClient{svc: svc, agentID: agentID, onProfile: onProfile}
}

// Run opens the ReceivePolicy stream and forwards each received profile to
// onProfile. Profile application is serialised via a worker goroutine so that
// concurrent deliveries cannot reorder (H4 fix).
// On stream errors it reconnects with exponential backoff (1s → 2s → … → 30s)
// until ctx is cancelled.
func (c *PolicyClient) Run(ctx context.Context) {
	// H4 fix: serialise profile application through a buffered work channel so
	// profile P2 is never applied before profile P1 when both arrive in a burst.
	workCh := make(chan *gen.SurveillanceProfilePB, 8)
	go func() {
		for p := range workCh {
			if c.onProfile != nil {
				c.onProfile(p)
			}
		}
	}()
	defer close(workCh)

	delay := 1 * time.Second
	const maxDelay = 30 * time.Second

	for {
		err := c.runStream(ctx, workCh)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("policy stream error, reconnecting", "err", err, "delay", delay)
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func (c *PolicyClient) runStream(ctx context.Context, workCh chan<- *gen.SurveillanceProfilePB) error {
	stream, err := c.svc.ReceivePolicy(ctx, &gen.PolicyRequest{AgentId: c.agentID})
	if err != nil {
		return err
	}
	for {
		profile, err := stream.Recv()
		if err == io.EOF {
			// M3 fix: server-side EOF (e.g. rolling restart) triggers reconnect.
			return fmt.Errorf("policy: server closed stream")
		}
		if err != nil {
			return err
		}
		select {
		case workCh <- profile:
		case <-ctx.Done():
			return nil
		}
	}
}
