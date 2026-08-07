//go:build linux

package commands

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/collector"
)

const (
	cmdSetThrottle   = "SET_THROTTLE"
	cmdReloadProfile = "RELOAD_PROFILE"
	cmdTakeSnapshot  = "TAKE_SNAPSHOT"
)

// CommandClient maintains the server→agent command stream and dispatches
// commands to the collector manager.
type CommandClient struct {
	svc     gen.AgentServiceClient
	agentID []byte
	mgr     *collector.CollectorManager
}

// NewClient returns a CommandClient bound to the given agent service client.
func NewClient(svc gen.AgentServiceClient, agentID []byte, mgr *collector.CollectorManager) *CommandClient {
	return &CommandClient{svc: svc, agentID: agentID, mgr: mgr}
}

// Run opens the StreamCommands stream and dispatches each received command.
// On errors it reconnects with exponential backoff until ctx is cancelled.
func (c *CommandClient) Run(ctx context.Context) {
	delay := 1 * time.Second
	const maxDelay = 30 * time.Second

	for {
		err := c.runStream(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		slog.Warn("commands stream error, reconnecting", "err", err, "delay", delay)

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

func (c *CommandClient) runStream(ctx context.Context) error {
	stream, err := c.svc.StreamCommands(ctx, &gen.CommandRequest{AgentId: c.agentID})
	if err != nil {
		return err
	}
	for {
		cmd, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		c.dispatch(cmd)
	}
}

// dispatch handles a single received AgentCommand.
func (c *CommandClient) dispatch(cmd *gen.AgentCommand) {
	switch cmd.GetCommandType() {
	case cmdSetThrottle:
		var payload struct {
			Factor float64 `json:"factor"`
		}
		if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil {
			slog.Warn("set_throttle invalid payload", "err", err)
			return
		}
		c.mgr.SetThrottle(payload.Factor)
		slog.Info("throttle set from command", "factor", payload.Factor)
	case cmdReloadProfile:
		// Profile arrives via ReceivePolicy; just acknowledge here.
		slog.Info("reload_profile received — profile delivered via policy stream")
	case cmdTakeSnapshot:
		slog.Info("snapshot requested")
	default:
		slog.Warn("unknown command", "type", cmd.GetCommandType())
	}
}
