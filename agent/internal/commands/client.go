//go:build linux

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/backoff"
	"github.com/oseye/agent/internal/collector"
	"github.com/oseye/agent/internal/responder"
)

const (
	cmdSetThrottle      = "SET_THROTTLE"
	cmdReloadProfile    = "RELOAD_PROFILE"
	cmdTakeSnapshot     = "TAKE_SNAPSHOT"
	cmdDisableAutonomy  = "DISABLE_AUTONOMY"
	cmdEnableAutonomy   = "ENABLE_AUTONOMY"

	// Response commands — act-then-notify.
	// BLOCK_IP and QUARANTINE_FILE are executed autonomously by the agent.
	// KILL_PROCESS requires explicit server order (ask-then-act at server level).
	cmdBlockIP        = "BLOCK_IP"
	cmdUnblockIP      = "UNBLOCK_IP"
	cmdQuarantineFile = "QUARANTINE_FILE"
	cmdRestoreFile    = "RESTORE_FILE"
	cmdKillProcess    = "KILL_PROCESS"
)

// KillSwitcher allows the command client to toggle the autonomy kill switch.
type KillSwitcher interface {
	Disable()
	Enable()
}

// CommandClient maintains the server→agent command stream and dispatches
// commands to the collector manager and response executor.
type CommandClient struct {
	svc           gen.AgentServiceClient
	agentID       []byte
	mgr           *collector.CollectorManager
	state         *responder.StateStore
	dedup         *responder.Deduplicator
	reporter      *responder.Reporter
	quarantineDir string
	killSwitch    KillSwitcher
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
	killSwitch ...KillSwitcher,
) *CommandClient {
	c := &CommandClient{
		svc:           svc,
		agentID:       agentID,
		mgr:           mgr,
		state:         state,
		dedup:         dedup,
		reporter:      reporter,
		quarantineDir: quarantineDir,
	}
	if len(killSwitch) > 0 {
		c.killSwitch = killSwitch[0]
	}
	return c
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

	case cmdDisableAutonomy:
		if c.killSwitch != nil {
			c.killSwitch.Disable()
		}
		slog.Warn("autonomy disabled by server command")
		c.reporter.Send(cmd.GetCommandId(), "executed", "")

	case cmdEnableAutonomy:
		if c.killSwitch != nil {
			c.killSwitch.Enable()
		}
		slog.Info("autonomy re-enabled by server command")
		c.reporter.Send(cmd.GetCommandId(), "executed", "")

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

	// GO-003: reject CIDR ranges and validate the IP address.
	if strings.Contains(payload.IP, "/") {
		slog.Warn("block_ip: CIDR ranges not accepted", "ip", payload.IP)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Sprintf("block_ip: CIDR ranges not accepted: %s", payload.IP))
		return
	}
	parsed := net.ParseIP(strings.TrimSpace(payload.IP))
	if parsed == nil {
		slog.Warn("block_ip: invalid IP address", "ip", payload.IP)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Sprintf("block_ip: invalid IP address: %s", payload.IP))
		return
	}
	canonicalIP := parsed.String()

	// CIA — Déduplication : one block per IP per 60s.
	if !c.dedup.Allow(cmdBlockIP, canonicalIP) {
		slog.Info("block_ip: deduplicated", "ip", canonicalIP)
		return
	}

	// CIA — Intégrité : persist state BEFORE execution so we can recover on restart.
	statePayload := map[string]any{"ip": canonicalIP}
	initialState := responder.ActionState{
		CommandID:   cmd.GetCommandId(),
		CommandType: cmdBlockIP,
		Payload:     statePayload,
		Status:      "pending",
		CreatedAt:   nowNs(),
	}
	if err := c.state.Save(initialState); err != nil {
		slog.Warn("block_ip: state save failed", "err", err)
	}

	handle, err := responder.BlockIP(canonicalIP)
	if err != nil {
		slog.Error("block_ip: failed", "ip", canonicalIP, "err", err)
		_ = c.state.MarkFailed(cmd.GetCommandId())
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	// Persist nft handle for targeted per-rule removal on unblock.
	if handle != "" {
		statePayload["nft_handle"] = handle
		_ = c.state.Save(responder.ActionState{
			CommandID:   cmd.GetCommandId(),
			CommandType: cmdBlockIP,
			Payload:     statePayload,
			Status:      "pending",
			CreatedAt:   initialState.CreatedAt,
		})
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

	// Canonicalize IP before state lookup and executor call.
	parsed := net.ParseIP(strings.TrimSpace(payload.IP))
	if parsed == nil {
		slog.Warn("unblock_ip: invalid IP", "ip", payload.IP)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Sprintf("unblock_ip: invalid IP: %s", payload.IP))
		return
	}
	canonicalIP := parsed.String()

	// Retrieve the nft rule handle and original command ID stored when BlockIP was executed.
	blockCommandID := ""
	handle := ""
	if actions, err := c.state.GetExecuted(); err == nil {
		for _, a := range actions {
			if a.CommandType == cmdBlockIP {
				if ip, ok := a.Payload["ip"].(string); ok && ip == canonicalIP {
					blockCommandID = a.CommandID
					if h, ok := a.Payload["nft_handle"].(string); ok {
						handle = h
					}
					break
				}
			}
		}
	}

	if err := responder.UnblockIP(canonicalIP, handle); err != nil {
		slog.Error("unblock_ip: failed", "ip", canonicalIP, "err", err)
		c.reporter.Send(cmd.GetCommandId(), "failed", err.Error())
		return
	}

	// NE-R-03: MarkRolledBack must use the BLOCK_IP command ID (the one that was
	// persisted in state), not the UNBLOCK_IP command ID which was never stored.
	if blockCommandID != "" {
		_ = c.state.MarkRolledBack(blockCommandID)
	}
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

	// GO-002: validate source path against traversal attacks before any action.
	clean := filepath.Clean(payload.Path)
	if !filepath.IsAbs(clean) || !isAllowedPath(clean) {
		slog.Warn("quarantine_file: path traversal rejected", "path", payload.Path)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Sprintf("quarantine: path traversal rejected: %s", payload.Path))
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

	// NE-R-04: clean both sides before the prefix check so that a raw
	// quarantineDir with a trailing slash or a sibling name (e.g.
	// "/var/quarantine2/evil") cannot bypass the containment guard.
	cleanDir := filepath.Clean(c.quarantineDir) + string(filepath.Separator)
	cleanQ := filepath.Clean(payload.QuarantinePath)
	if !strings.HasPrefix(cleanQ, cleanDir) {
		slog.Warn("restore_file: quarantine path outside quarantine dir", "path", payload.QuarantinePath)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Errorf("restore: path outside quarantine dir: %s", payload.QuarantinePath).Error())
		return
	}

	// CORE-003: original_path must be absolute before any further validation.
	if !filepath.IsAbs(payload.OriginalPath) {
		slog.Warn("restore_file: original path is not absolute", "path", payload.OriginalPath)
		c.reporter.Send(cmd.GetCommandId(), "failed",
			fmt.Sprintf("restore_file: original_path must be absolute: %s", payload.OriginalPath))
		return
	}

	// GO-004: reject restoration to dangerous system directories.
	cleanO := filepath.Clean(payload.OriginalPath)
	if isDangerousPath(cleanO) {
		slog.Warn("restore_file: dangerous original path rejected", "path", payload.OriginalPath)
		c.reporter.Send(cmd.GetCommandId(), "failed", fmt.Sprintf("restore_file: dangerous destination rejected: %s", payload.OriginalPath))
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
	if err := json.Unmarshal(cmd.GetPayloadJson(), &payload); err != nil || payload.PID < 2 {
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

// isAllowedPath returns true if p starts with a permitted filesystem prefix for
// quarantine source paths. Mirrors the check in responder.isAllowedPath.
func isAllowedPath(p string) bool {
	for _, prefix := range []string{"/var", "/tmp", "/home", "/opt", "/srv", "/run"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// isDangerousPath returns true if p targets a critical system directory that
// must never be used as a restore destination.
func isDangerousPath(p string) bool {
	for _, prefix := range []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func nowNs() int64 { return time.Now().UnixNano() }
