//go:build linux

package policy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/backoff"
	"google.golang.org/grpc/status"
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
		defer func() {
			if r := recover(); r != nil {
				slog.Error("policy worker panic", "err", r)
			}
		}()
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
			grpcCode := status.Code(err).String()
			slog.Warn("policy stream error, reconnecting", "err", err, "grpc_code", grpcCode, "delay", delay)
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

func (c *PolicyClient) runStream(ctx context.Context, workCh chan<- *gen.SurveillanceProfilePB) error {
	stream, err := c.svc.ReceivePolicy(ctx, &gen.PolicyRequest{AgentId: c.agentID})
	if err != nil {
		return err
	}
	// policy integrity delegated to mTLS transport: ReceivePolicy runs over a
	// mutual-TLS gRPC channel (client cert verified by server, server cert verified
	// by agent CA pool). No additional application-layer signature is present on
	// SurveillanceProfilePB; authenticity of the payload is guaranteed by the
	// authenticated channel itself. Ensure the gRPC ClientConn is constructed with
	// credentials.NewTLS using the agent key-pair and the CA pool (see agent/cmd).
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
