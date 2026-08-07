//go:build linux

package policy

import (
	"context"
	"io"
	"log/slog"
	"time"

	gen "github.com/oseye/agent/gen"
)

// PolicyClient maintains the server→agent SurveillanceProfile stream and
// applies profile updates via onProfile (non-blocking).
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
// onProfile. On stream errors it reconnects with exponential backoff
// (1s → 2s → 4s → 30s max) until ctx is cancelled.
func (c *PolicyClient) Run(ctx context.Context) {
	delay := 1 * time.Second
	const maxDelay = 30 * time.Second

	for {
		err := c.runStream(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
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

func (c *PolicyClient) runStream(ctx context.Context) error {
	stream, err := c.svc.ReceivePolicy(ctx, &gen.PolicyRequest{AgentId: c.agentID})
	if err != nil {
		return err
	}
	for {
		profile, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if c.onProfile != nil {
			go c.onProfile(profile)
		}
	}
}
