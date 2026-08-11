//go:build linux

package commands

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/backoff"
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/responder"
)

const (
	cmdSetThrottle   = "SET_THROTTLE"
	cmdReloadProfile = "RELOAD_PROFILE"
	cmdTakeSnapshot  = "TAKE_SNAPSHOT"

	// Response commands — act-then-notify.
	// BLOCK_IP and QUARANTINE_FILE are executed autonomously by the agent.
	// KILL_PROCESS requires explicit server order (ask-then-act at server level).
	cmdBlockIP        = "BLOCK_IP"
	cmdUnblockIP      = "UNBLOCK_IP"
	cmdQuarantineFile = "QUARANTINE_FILE"
	cmdRestoreFile    = "RESTORE_FILE"
	cmdKillProcess    = "KILL_PROCESS"
)

// CommandClient maintains the server→agent command stream and dispatches
// commands to the collector manager and response executor.
type CommandClient struct {
	svc          gen.AgentServiceClient
	agentID      []byte
	mgr          *collector.CollectorManager
	state        *responder.StateStore
	dedup        *responder.Deduplicator
	reporter     *responder.Reporter
	quarantineDir string
}

// NewClient returns a CommandClient bound to the given agent service client.
func NewClient(
	svc gen.AgentServiceClient,
	agentID []byte,
	mgr *collector.CollectorManager,
	state *responder.StateStore,
	dedup *responder.Deduplicator,
	reporter *responder.Reporter,
	quarantineDir string,
) *CommandClient {
	return &CommandClient{
		svc:           svc,
		agentID:       agentID,
		mgr:           mgr,
		state:         state,
		dedup:         dedup,
		reporter:      reporter,
		quarantineDir: quarantineDir,
	}
}

// Run opens the StreamCommands stream and dispatches each received command.
// On errors it reconnects with full-jitter backoff until ctx is cancelled.
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
		delay = backoff.Next(delay, maxDelay)
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
		slog.Info("reload_profile received — profile delivered via policy stream")

	case cmdTakeSnapshot:
		slog.Info("snapshot requested")

	case cmdBlockIP:
		c.handleBlockIP(cmd)

	case cmdUnblockIP:
		c.handleUnblockIP(cmd)

	case cmdQuarantineFile:
		c.handleQuarantineFile(cmd)

	case cmdRestoreFile:
		c.handleRestoreFile(cmd)

	case cmdKillProcess:
		// CIA — ask-then-act : kill is only triggered by an explicit server command
		// (after human approval at score > 80). Never executed autonomously.
		c.handleKillProcess(cmd)

	default:
		slog.Warn("unknown command", "type", cmd.GetCommandType())
	}
}

// --- Response command handlers ---

func (c *CommandClient) handleBlockIP(cmd *gen.AgentCommand) {
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil || payload.IP == "" {
		slog.Warn("block_ip: invalid payload", "err", err)
		return
	}

	// CIA — Déduplication : one block per IP per 60s.
	if !c.dedup.Allow(cmdBlockIP, payload.IP) {
		slog.Info("block_ip: deduplicated", "ip", payload.IP)
		return
	}

	// CIA — Intégrité : persist state BEFORE execution so we can recover on restart.
	state := responder.ActionState{
		CommandID:   cmd.GetCommandId(),
		CommandType: cmdBlockIP,
		Payload:     map[string]any{"ip": payload.IP},
		Status:      "pending",
		CreatedAt:   nowNs(),
	}
	if err := c.state.Save(state); err != nil {
		slog.Warn("block_ip: state save failed", "err", err)
	}

	if err := responder.BlockIP(payload.IP); err != nil {
		slog.Error("block_ip: failed", "ip", payload.IP, "err", err)
		_ = c.state.MarkFailed(cmd.GetCommandId())
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	_ = c.state.MarkExecuted(cmd.GetCommandId(), nowNs())
	c.reporter.Send(cmd.GetCommandId(), "executed", "")
}

func (c *CommandClient) handleUnblockIP(cmd *gen.AgentCommand) {
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil || payload.IP == "" {
		slog.Warn("unblock_ip: invalid payload", "err", err)
		return
	}

	if err := responder.UnblockIP(payload.IP); err != nil {
		slog.Error("unblock_ip: failed", "ip", payload.IP, "err", err)
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	_ = c.state.MarkRolledBack(cmd.GetCommandId())
	c.reporter.Send(cmd.GetCommandId(), "rolled_back", "")
}

func (c *CommandClient) handleQuarantineFile(cmd *gen.AgentCommand) {
	var payload struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil || payload.Path == "" {
		slog.Warn("quarantine_file: invalid payload", "err", err)
		return
	}

	if !c.dedup.Allow(cmdQuarantineFile, payload.Path) {
		slog.Info("quarantine_file: deduplicated", "path", payload.Path)
		return
	}

	state := responder.ActionState{
		CommandID:   cmd.GetCommandId(),
		CommandType: cmdQuarantineFile,
		Payload:     map[string]any{"path": payload.Path},
		Status:      "pending",
		CreatedAt:   nowNs(),
	}
	if err := c.state.Save(state); err != nil {
		slog.Warn("quarantine_file: state save failed", "err", err)
	}

	quarantinePath, err := responder.QuarantineFile(payload.Path, c.quarantineDir)
	if err != nil {
		slog.Error("quarantine_file: failed", "path", payload.Path, "err", err)
		_ = c.state.MarkFailed(cmd.GetCommandId())
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	// Update state to record quarantine path for later restoration.
	updatedState := responder.ActionState{
		CommandID:   cmd.GetCommandId(),
		CommandType: cmdQuarantineFile,
		Payload:     map[string]any{"path": payload.Path, "quarantine_path": quarantinePath},
		Status:      "executed",
		CreatedAt:   state.CreatedAt,
	}
	if err := c.state.Save(updatedState); err != nil {
		slog.Warn("quarantine_file: state update failed", "err", err)
	}

	c.reporter.Send(cmd.GetCommandId(), "executed", "")
}

func (c *CommandClient) handleRestoreFile(cmd *gen.AgentCommand) {
	var payload struct {
		QuarantinePath string `json:"quarantine_path"`
		OriginalPath   string `json:"original_path"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil {
		slog.Warn("restore_file: invalid payload", "err", err)
		return
	}

	if err := responder.RestoreFile(payload.QuarantinePath, payload.OriginalPath); err != nil {
		slog.Error("restore_file: failed", "err", err)
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	_ = c.state.MarkRolledBack(cmd.GetCommandId())
	c.reporter.Send(cmd.GetCommandId(), "rolled_back", "")
}

func (c *CommandClient) handleKillProcess(cmd *gen.AgentCommand) {
	var payload struct {
		PID         int    `json:"pid"`
		ProcessName string `json:"process_name"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil || payload.PID <= 0 {
		slog.Warn("kill_process: invalid payload", "err", err)
		return
	}

	// CIA — Intégrité : verify PID still belongs to expected process before killing.
	if err := responder.KillProcess(payload.PID, payload.ProcessName); err != nil {
		slog.Error("kill_process: failed", "pid", payload.PID, "err", err)
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	c.reporter.Send(cmd.GetCommandId(), "executed", "")
}

func nowNs() int64 { return time.Now().UnixNano() }
