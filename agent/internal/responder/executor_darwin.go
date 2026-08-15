//go:build darwin

// Package responder — macOS response actions.
//
// BlockIP:        pf firewall via pfctl anchor "oseye"
// UnblockIP:      Flush the per-IP anchor
// KillProcess:    SIGKILL after verifying process name via ps(1)
// QuarantineFile: Move + chmod 000
// RestoreFile:    Move back + restore permissions
package responder

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func nowNs() int64 { return time.Now().UnixNano() }

// isAllowedPath returns true for absolute paths outside macOS system roots.
// Blocks system directories to prevent bricking the host.
func isAllowedPath(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	forbidden := []string{
		"/sbin/",
		"/usr/sbin/",
		"/usr/bin/",
		"/usr/libexec/",
		"/System/",
		"/Library/Apple/",
		"/private/var/db/",
	}
	for _, f := range forbidden {
		if strings.HasPrefix(p, f) {
			return false
		}
	}
	return true
}

// BlockIP adds a pf block rule via pfctl using the "oseye" anchor.
// Returns the per-IP anchor path as handle for UnblockIP.
// Requires root / com.apple.security.network.client entitlement.
func BlockIP(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if !isValidIP(ip) {
		return "", fmt.Errorf("block_ip: invalid IP: %s", ip)
	}

	// Ensure pf is enabled
	exec.Command("pfctl", "-e").Run() //nolint:errcheck

	// Each IP gets its own sub-anchor so rules can be removed individually.
	anchor := "oseye/" + strings.ReplaceAll(ip, ":", "_")
	rule := fmt.Sprintf("block drop out quick from any to %s\n", ip)

	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("block_ip: pfctl: %s: %w", strings.TrimSpace(string(out)), err)
	}
	slog.Info("ip_blocked", "ip", ip, "anchor", anchor)
	return anchor, nil
}

// UnblockIP flushes the per-IP anchor created by BlockIP.
func UnblockIP(ip, handle string) error {
	anchor := handle
	if anchor == "" {
		anchor = "oseye/" + strings.ReplaceAll(strings.TrimSpace(ip), ":", "_")
	}
	cmd := exec.Command("pfctl", "-a", anchor, "-F", "all")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("unblock_ip: pfctl: %s: %w", strings.TrimSpace(string(out)), err)
	}
	slog.Info("ip_unblocked", "ip", ip, "anchor", anchor)
	return nil
}

// KillProcess sends SIGKILL to pid after verifying the process name matches
// expectedProcessName — prevents killing a recycled PID.
func KillProcess(pid int, expectedProcessName string) error {
	if pid < 2 {
		return fmt.Errorf("kill_process: refusing to kill system process (pid %d)", pid)
	}

	actual, err := processName(pid)
	if err != nil {
		return fmt.Errorf("kill_process: get name for pid %d: %w", pid, err)
	}

	expected := filepath.Base(expectedProcessName)
	if filepath.Base(actual) != expected {
		return fmt.Errorf("kill_process: pid %d is %q, expected %q — refusing", pid, actual, expected)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("kill_process: find pid %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill_process: SIGKILL pid %d: %w", pid, err)
	}
	slog.Info("process_killed", "pid", pid, "name", actual)
	return nil
}

// QuarantineFile moves path to quarantineDir and sets permissions to 000.
func QuarantineFile(path, quarantineDir string) (string, error) {
	clean := filepath.Clean(path)
	if !isAllowedPath(clean) {
		return "", fmt.Errorf("quarantine: path rejected: %s", path)
	}

	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return "", fmt.Errorf("quarantine: mkdir: %w", err)
	}

	base := filepath.Base(path)
	dst := filepath.Join(quarantineDir, fmt.Sprintf("%d_%s", nowNs(), base))

	if err := os.Rename(path, dst); err != nil {
		return "", fmt.Errorf("quarantine: move %q → %q: %w", path, dst, err)
	}
	if err := os.Chmod(dst, 0o000); err != nil {
		slog.Warn("quarantine: chmod failed", "dst", dst, "err", err)
	}
	slog.Info("file_quarantined", "original", path, "quarantine", dst)
	return dst, nil
}

// RestoreFile moves a quarantined file back to its original location.
func RestoreFile(quarantinePath, originalPath string) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(originalPath); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(quarantinePath, mode); err != nil {
		slog.Warn("restore: chmod failed", "err", err)
	}
	if err := os.Rename(quarantinePath, originalPath); err != nil {
		return fmt.Errorf("restore: move %q → %q: %w", quarantinePath, originalPath, err)
	}
	slog.Info("file_restored", "path", originalPath)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// processName returns the basename of the executable for pid via ps(1).
func processName(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=").Output()
	if err != nil {
		return "", fmt.Errorf("ps: %w", err)
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return "", fmt.Errorf("pid %d not found", pid)
	}
	return name, nil
}

// isValidIP uses net.ParseIP for correct octet-range validation (0-255).
// Rejects CIDR notation.
func isValidIP(ip string) bool {
	if strings.Contains(ip, "/") {
		return false
	}
	return net.ParseIP(ip) != nil
}
