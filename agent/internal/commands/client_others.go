//go:build windows || darwin

// Package commands — cross-platform command client (Windows + macOS).
// Handles: SET_THROTTLE, TAKE_SNAPSHOT, BLOCK_IP, UNBLOCK_IP,
//          QUARANTINE_FILE, RESTORE_FILE, KILL_PROCESS.
// Autonomy / DISABLE_AUTONOMY / ENABLE_AUTONOMY are Linux-only.
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/backoff"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/config"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/responder"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/snapshot"
)

const (
	cmdSetThrottle      = "SET_THROTTLE"
	cmdTakeSnapshot     = "TAKE_SNAPSHOT"
	cmdBlockIP          = "BLOCK_IP"
	cmdUnblockIP        = "UNBLOCK_IP"
	cmdQuarantineFile   = "QUARANTINE_FILE"
	cmdRestoreFile      = "RESTORE_FILE"
	cmdKillProcess      = "KILL_PROCESS"
)

// KillSwitcher is a no-op interface on non-Linux platforms (no autonomy engine).
type KillSwitcher interface {
	Disable()
	Enable()
}

// CommandClient streams commands from the server and dispatches them.
type CommandClient struct {
	svc           gen.AgentServiceClient
	agentID       []byte
	mgr           *collector.CollectorManager
	quarantineDir string
	cfg           *config.Config

	// snapshotSem caps concurrent snapshot goroutines at 1 to prevent flooding.
	snapshotSem chan struct{}
	// blockedIPs deduplicates BLOCK_IP commands for the same IP.
	blockedIPs sync.Map
}

// NewClient returns a CommandClient.
func NewClient(
	svc gen.AgentServiceClient,
	agentID []byte,
	mgr *collector.CollectorManager,
	_ interface{}, // StateStore — not used on non-Linux
	_ interface{}, // Deduplicator — not used on non-Linux
	_ interface{}, // Reporter — not used on non-Linux
	quarantineDir string,
	_ ...KillSwitcher,
) *CommandClient {
	return &CommandClient{
		svc:           svc,
		agentID:       agentID,
		mgr:           mgr,
		quarantineDir: quarantineDir,
		snapshotSem:   make(chan struct{}, 1), // max 1 concurrent snapshot
	}
}

// WithConfig attaches agent config (used by snapshot POST).
func (c *CommandClient) WithConfig(cfg *config.Config) *CommandClient {
	c.cfg = cfg
	return c
}

// Run opens the StreamCommands stream with full-jitter backoff reconnect.
func (c *CommandClient) Run(ctx context.Context) {
	delay := time.Second
	const maxDelay = 30 * time.Second
	for {
		if err := c.runStream(ctx); err == nil || ctx.Err() != nil {
			return
		}
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

func (c *CommandClient) dispatch(cmd *gen.AgentCommand) {
	switch cmd.GetCommandType() {
	case cmdSetThrottle:
		var p struct {
			Factor float64 `json:"factor"`
		}
		if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err == nil && c.mgr != nil {
			c.mgr.SetThrottle(p.Factor)
		}

	case cmdTakeSnapshot:
		// Non-blocking: skip if a snapshot is already in progress.
		select {
		case c.snapshotSem <- struct{}{}:
			go func() {
				defer func() { <-c.snapshotSem }()
				c.handleSnapshot(cmd)
			}()
		default:
			slog.Warn("snapshot already in progress, skipping")
		}

	case cmdBlockIP:
		go c.handleBlockIP(cmd)

	case cmdUnblockIP:
		go c.handleUnblockIP(cmd)

	case cmdQuarantineFile:
		go c.handleQuarantineFile(cmd)

	case cmdRestoreFile:
		go c.handleRestoreFile(cmd)

	case cmdKillProcess:
		go c.handleKillProcess(cmd)

	default:
		slog.Warn("unknown command", "type", cmd.GetCommandType())
	}
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (c *CommandClient) handleSnapshot(cmd *gen.AgentCommand) {
	var p struct{ CaseID string `json:"case_id"` }
	_ = json.Unmarshal(cmd.GetPayloadJson(), &p)

	agentIDHex := fmt.Sprintf("%x", c.agentID)
	snap, err := snapshot.Collect(agentIDHex, p.CaseID)
	if err != nil {
		slog.Error("snapshot_collect_failed", "err", err)
		return
	}
	slog.Info("snapshot_collected", "processes", len(snap.Processes), "connections", len(snap.Connections))

	if c.cfg == nil || c.cfg.APIAddr == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := snapshot.Post(ctx, snap, c.cfg.APIAddr, snapshot.TLSConfig{
		CertFile: c.cfg.TLSCertFile,
		KeyFile:  c.cfg.TLSKeyFile,
		CAFile:   c.cfg.CACertFile,
	}); err != nil {
		slog.Error("snapshot_post_failed", "err", err)
	}
}

func (c *CommandClient) handleBlockIP(cmd *gen.AgentCommand) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err != nil || p.IP == "" {
		slog.Warn("block_ip: invalid payload")
		return
	}
	// Dedup: skip if this IP is already blocked to prevent rule accumulation.
	if _, loaded := c.blockedIPs.LoadOrStore(p.IP, struct{}{}); loaded {
		slog.Debug("block_ip: already blocked, skipping", "ip", p.IP)
		return
	}
	handle, err := responder.BlockIP(p.IP)
	if err != nil {
		c.blockedIPs.Delete(p.IP) // remove so a retry is possible
		slog.Error("block_ip failed", "ip", p.IP, "err", err)
		return
	}
	_ = handle
}

func (c *CommandClient) handleUnblockIP(cmd *gen.AgentCommand) {
	var p struct {
		IP     string `json:"ip"`
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err != nil || p.IP == "" {
		slog.Warn("unblock_ip: invalid payload")
		return
	}
	if err := responder.UnblockIP(p.IP, p.Handle); err != nil {
		slog.Error("unblock_ip failed", "ip", p.IP, "err", err)
		return
	}
	c.blockedIPs.Delete(p.IP)
}

func (c *CommandClient) handleQuarantineFile(cmd *gen.AgentCommand) {
	var p struct {
		Path         string `json:"path"`
		QuarantineDir string `json:"quarantine_dir"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err != nil || p.Path == "" {
		slog.Warn("quarantine_file: invalid payload")
		return
	}
	dir := p.QuarantineDir
	if dir == "" && c.cfg != nil {
		dir = c.cfg.QuarantineDir
	}
	if _, err := responder.QuarantineFile(p.Path, dir); err != nil {
		slog.Error("quarantine_file failed", "path", p.Path, "err", err)
	}
}

func (c *CommandClient) handleRestoreFile(cmd *gen.AgentCommand) {
	var p struct {
		QuarantinePath string `json:"quarantine_path"`
		OriginalPath   string `json:"original_path"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err != nil {
		slog.Warn("restore_file: invalid payload")
		return
	}
	if err := responder.RestoreFile(p.QuarantinePath, p.OriginalPath); err != nil {
		slog.Error("restore_file failed", "err", err)
	}
}

func (c *CommandClient) handleKillProcess(cmd *gen.AgentCommand) {
	var p struct {
		PID         int    `json:"pid"`
		ProcessName string `json:"process_name"`
	}
	if err := json.Unmarshal(cmd.GetPayloadJson(), &p); err != nil || p.PID == 0 {
		slog.Warn("kill_process: invalid payload")
		return
	}
	if err := responder.KillProcess(p.PID, p.ProcessName); err != nil {
		slog.Error("kill_process failed", "pid", p.PID, "err", err)
	}
}
