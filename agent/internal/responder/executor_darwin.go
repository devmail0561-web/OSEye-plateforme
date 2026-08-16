//go:build darwin

// Package responder — macOS response actions.
//
// BlockIP:        pf firewall via pfctl anchor "oseye"
// UnblockIP:      Flush the per-IP anchor
// KillProcess:    SIGKILL after verifying process name via sysctl(3) KERN_PROC_PID
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

	"golang.org/x/sys/unix"
)

func nowNs() int64 { return time.Now().UnixNano() }

// isAllowedPath returns true if p starts with one of the permitted filesystem
// prefixes for quarantine source paths on macOS (positive allowlist).
// Paths outside this allowlist are rejected to prevent bricking the host.
func isAllowedPath(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	// macOS temp / runtime directories that are safe to quarantine from.
	for _, prefix := range []string{
		"/tmp",
		"/var/tmp",
		"/private/tmp",
		"/private/var/tmp",
		"/var/folders",
	} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	// Allow user home directories, but exclude ~/Library to avoid corrupting
	// keychains, Preferences, and app caches.
	if strings.HasPrefix(p, "/Users/") {
		// Split off the username component and check the next segment.
		// e.g. "/Users/alice/Library/…" → ["alice", "Library", …]
		rest := strings.TrimPrefix(p, "/Users/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 && parts[1] == "Library" {
			return false
		}
		return true
	}
	return false
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
//
// Process name is read via sysctl(3) KERN_PROC_PID (in-kernel, atomic) instead
// of a ps(1) subprocess, which substantially shrinks the TOCTOU window: there
// is no fork/exec between the name check and the signal, and the PID cannot be
// recycled between the two syscalls without the kernel knowing.
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
	// Validate and clean the target path to prevent path traversal attacks.
	cleanOrig := filepath.Clean(originalPath)
	if !isAllowedPath(cleanOrig) {
		return fmt.Errorf("restore: originalPath rejected: %s", originalPath)
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(cleanOrig); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(quarantinePath, mode); err != nil {
		slog.Warn("restore: chmod failed", "err", err)
	}
	if err := os.Rename(quarantinePath, cleanOrig); err != nil {
		return fmt.Errorf("restore: move %q → %q: %w", quarantinePath, cleanOrig, err)
	}
	slog.Info("file_restored", "path", cleanOrig)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// processName returns the process name for pid via sysctl(3) KERN_PROC_PID.
// Using the sysctl syscall directly avoids the TOCTOU window that a ps(1)
// subprocess would introduce: the kernel reads the kinfo_proc atomically and
// there is no external process whose scheduling creates a gap between the name
// check and the subsequent kill.
func processName(pid int) (string, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", fmt.Errorf("sysctl kern.proc.pid %d: %w", pid, err)
	}
	// P_comm is a NUL-terminated [17]byte containing the process short name.
	name := unix.ByteSliceToString(kp.Proc.P_comm[:])
	if name == "" {
		return "", fmt.Errorf("pid %d: empty comm (process may have exited)", pid)
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
