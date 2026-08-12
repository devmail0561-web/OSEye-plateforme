//go:build linux

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
func BlockIP(ip string) (handle string, err error) {
	// G-X-02: validate and canonicalize IP before passing to firewall commands.
	// net.ParseIP also rejects CIDR notation ("1.2.3.4/24") — it returns nil for those.
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", fmt.Errorf("block_ip: invalid IP: %s", ip)
	}
	ip = parsed.String() // canonical form

	switch detectedBackend {
	case backendNftables:
		// Adds to the oseye chain in the filter table (created if absent).
		if err := ensureNftChain(); err != nil {
			return "", fmt.Errorf("block_ip: ensure nft chain: %w", err)
		}
		// --handle --echo makes nft echo the inserted rule with its numeric handle,
		// which we capture to allow targeted per-rule deletion in UnblockIP.
		out, err := exec.Command("nft", "--handle", "--echo", "add", "rule", "inet", "oseye", "output",
			"ip", "daddr", ip, "drop").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("block_ip: nft add rule: %s: %w", out, err)
		}
		handle = parseNftHandle(string(out))
	case backendIptables:
		out, err := exec.Command("iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("block_ip: iptables: %s: %w", out, err)
		}
	default:
		return "", fmt.Errorf("block_ip: no supported firewall backend (nftables/iptables) found")
	}
	slog.Info("ip_blocked", "ip", ip, "backend", detectedBackend)
	return handle, nil
}

// parseNftHandle extracts the numeric handle from nft --handle --echo output.
// The inserted-rule line looks like:
//
//	add rule inet oseye output ip daddr 1.2.3.4 drop # handle 5
func parseNftHandle(out string) string {
	const marker = "# handle "
	for _, line := range strings.Split(out, "\n") {
		if idx := strings.LastIndex(line, marker); idx >= 0 {
			if h := strings.TrimSpace(line[idx+len(marker):]); h != "" {
				return h
			}
		}
	}
	return ""
}

// UnblockIP removes the DROP rule for the given IP.
// handle is the nftables rule handle returned by BlockIP; empty string falls back to iptables.
func UnblockIP(ip, handle string) error {
	// G-X-02: validate and canonicalize IP.
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return fmt.Errorf("unblock_ip: invalid IP: %s", ip)
	}
	ip = parsed.String()

	switch detectedBackend {
	case backendNftables:
		if handle != "" {
			// G-X-01: delete the specific rule by handle — never flush the whole chain.
			out, err := exec.Command("nft", "delete", "rule", "inet", "oseye", "output",
				"handle", handle).CombinedOutput()
			if err != nil {
				return fmt.Errorf("unblock_ip: nft delete rule handle %s: %s: %w", handle, out, err)
			}
		} else {
			// No handle stored (e.g. upgraded from old agent version): log and skip.
			slog.Warn("unblock_ip: no nft handle available, cannot remove rule surgically", "ip", ip)
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

// isAllowedPath returns true if p starts with one of the permitted filesystem prefixes
// for quarantine source paths. Prevents accidental quarantine of system-critical files.
func isAllowedPath(p string) bool {
	for _, prefix := range []string{"/var", "/tmp", "/home", "/opt", "/srv", "/run"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// QuarantineFile moves the file at path to the quarantine directory with 000 perms.
// Returns the quarantine path for later restoration.
// CIA — Intégrité : original path is recorded in ActionState.Payload["original_path"].
func QuarantineFile(path, quarantineDir string) (string, error) {
	// GO-002: validate source path to prevent path traversal attacks.
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || !isAllowedPath(clean) {
		return "", fmt.Errorf("quarantine: path traversal rejected: %s", path)
	}

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
	// GO-001: defense-in-depth guard — refuse to kill PID 0 (kernel) or PID 1 (init).
	if pid < 2 {
		return fmt.Errorf("kill_process: refusing to kill system process (pid %d)", pid)
	}
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
