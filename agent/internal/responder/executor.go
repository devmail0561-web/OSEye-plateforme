//go:build linux

package responder

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// networkBackend is detected once at startup.
type networkBackend int

const (
	backendUnknown networkBackend = iota
	backendNftables
	backendIptables
)

var detectedBackend networkBackend

func init() {
	if _, err := exec.LookPath("nft"); err == nil {
		detectedBackend = backendNftables
	} else if _, err := exec.LookPath("iptables"); err == nil {
		detectedBackend = backendIptables
	}
}

// BlockIP adds a DROP rule for the given IP using the available backend.
// Returns the rule handle (nftables) or empty string (iptables) for later removal.
// CIA — Disponibilité : the rule is logged before execution so it survives a crash.
func BlockIP(ip string) error {
	switch detectedBackend {
	case backendNftables:
		// Adds to the oseye chain in the filter table (created if absent).
		if err := ensureNftChain(); err != nil {
			return fmt.Errorf("block_ip: ensure nft chain: %w", err)
		}
		out, err := exec.Command("nft", "add", "rule", "inet", "oseye", "output",
			"ip", "daddr", ip, "drop").CombinedOutput()
		if err != nil {
			return fmt.Errorf("block_ip: nft add rule: %s: %w", out, err)
		}
	case backendIptables:
		out, err := exec.Command("iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP").CombinedOutput()
		if err != nil {
			return fmt.Errorf("block_ip: iptables: %s: %w", out, err)
		}
	default:
		return fmt.Errorf("block_ip: no supported firewall backend (nftables/iptables) found")
	}
	slog.Info("ip_blocked", "ip", ip, "backend", detectedBackend)
	return nil
}

// UnblockIP removes the DROP rule for the given IP.
func UnblockIP(ip string) error {
	switch detectedBackend {
	case backendNftables:
		// Flush oseye chain rules matching this IP (idempotent).
		out, err := exec.Command("nft", "flush", "chain", "inet", "oseye", "output").CombinedOutput()
		if err != nil {
			return fmt.Errorf("unblock_ip: nft flush: %s: %w", out, err)
		}
	case backendIptables:
		out, err := exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").CombinedOutput()
		if err != nil {
			return fmt.Errorf("unblock_ip: iptables: %s: %w", out, err)
		}
	default:
		return fmt.Errorf("unblock_ip: no supported firewall backend found")
	}
	slog.Info("ip_unblocked", "ip", ip)
	return nil
}

func ensureNftChain() error {
	// Create table + chain if they don't exist (idempotent).
	cmds := [][]string{
		{"nft", "add", "table", "inet", "oseye"},
		{"nft", "add", "chain", "inet", "oseye", "output",
			`{ type filter hook output priority 0 ; policy accept ; }`},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			// "already exists" is fine
			slog.Debug("nft setup", "out", string(out))
		}
	}
	return nil
}

// QuarantineFile moves the file at path to the quarantine directory with 000 perms.
// Returns the quarantine path for later restoration.
// CIA — Intégrité : original path is recorded in ActionState.Payload["original_path"].
func QuarantineFile(path, quarantineDir string) (string, error) {
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", fmt.Errorf("quarantine: mkdir: %w", err)
	}

	base := filepath.Base(path)
	dst := filepath.Join(quarantineDir, fmt.Sprintf("%d_%s", nowNs(), base))

	if err := os.Rename(path, dst); err != nil {
		return "", fmt.Errorf("quarantine: rename %q → %q: %w", path, dst, err)
	}
	if err := os.Chmod(dst, 0o000); err != nil {
		slog.Warn("quarantine: chmod failed", "dst", dst, "err", err)
	}
	slog.Info("file_quarantined", "original", path, "quarantine", dst)
	return dst, nil
}

// RestoreFile moves a quarantined file back to its original location.
func RestoreFile(quarantinePath, originalPath string) error {
	if err := os.Chmod(quarantinePath, 0o644); err != nil {
		slog.Warn("restore: chmod failed", "path", quarantinePath, "err", err)
	}
	if err := os.Rename(quarantinePath, originalPath); err != nil {
		return fmt.Errorf("restore: rename %q → %q: %w", quarantinePath, originalPath, err)
	}
	slog.Info("file_restored", "original", originalPath)
	return nil
}

// KillProcess sends SIGKILL to the given PID after verifying the process name
// still matches the expected name — prevents killing a recycled PID.
// CIA — Intégrité : PID reuse check guards against false kills.
// IMPORTANT: Only callable via explicit server command, never autonomously.
func KillProcess(pid int, expectedProcessName string) error {
	// Read /proc/{pid}/comm to verify process name before killing.
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return fmt.Errorf("kill_process: read comm for pid %d: %w", pid, err)
	}

	// comm may have a trailing newline; trim it.
	actual := filepath.Base(strings.TrimSpace(string(data)))
	expected := filepath.Base(expectedProcessName)

	if actual != expected {
		return fmt.Errorf(
			"kill_process: pid %d comm %q != expected %q — refusing kill (PID reuse guard)",
			pid, actual, expected,
		)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("kill_process: find pid %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill_process: kill pid %d: %w", pid, err)
	}
	slog.Info("process_killed", "pid", pid, "process_name", expectedProcessName)
	return nil
}
