//go:build windows

// Package responder — Windows response actions.
//
// BlockIP:        Windows Defender Firewall via `netsh advfirewall`
// UnblockIP:      Delete the named outbound rule
// KillProcess:    TerminateProcess after verifying image name
// QuarantineFile: Move + deny access via icacls
// RestoreFile:    Move back + restore access
package responder

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ruleNamePrefix is prepended to every firewall rule so we can find it later.
const ruleNamePrefix = "OSEye-block-"

func nowNs() int64 { return time.Now().UnixNano() }

// isAllowedPath returns true for absolute paths outside Windows system roots.
// Blocks quarantining of system directories to prevent bricking the host.
func isAllowedPath(p string) bool {
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return false
	}
	// Reject any residual ".." component after cleaning (defence-in-depth).
	if strings.Contains(clean, "..") {
		return false
	}
	// Reject NT namespace device/junction paths (\\?\ and \\.\).
	if strings.HasPrefix(clean, `\\.`) || strings.HasPrefix(clean, `\\?`) {
		return false
	}
	// Require a known drive-letter prefix: <letter>:\ (e.g. C:\ or D:\).
	if len(clean) < 3 || clean[1] != ':' || clean[2] != '\\' {
		return false
	}
	driveLetter := strings.ToUpper(string(clean[0]))
	knownDrives := []string{"C", "D"}
	driveOK := false
	for _, d := range knownDrives {
		if driveLetter == d {
			driveOK = true
			break
		}
	}
	if !driveOK {
		return false
	}
	// Block entire Windows system directory trees.
	forbidden := []string{
		`C:\Windows\System32`,
		`C:\Windows\SysWOW64`,
		`C:\Windows\WinSxS`,
		`C:\Windows\Boot`,
		`C:\Program Files\Windows Defender`,
	}
	cleanLower := strings.ToLower(filepath.ToSlash(clean))
	for _, f := range forbidden {
		if strings.HasPrefix(cleanLower, strings.ToLower(filepath.ToSlash(f))) {
			return false
		}
	}
	return true
}

// BlockIP adds an outbound Windows Firewall rule to block traffic to ip.
// Returns the rule name as handle for later removal by UnblockIP.
func BlockIP(ip string) (string, error) {
	parsed, err := validateIP(ip)
	if err != nil {
		return "", err
	}
	ip = parsed

	ruleName := ruleNamePrefix + ip
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=out",
		"action=block",
		"remoteip="+ip,
		"protocol=any",
		"enable=yes",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("block_ip: netsh: %s: %w", strings.TrimSpace(string(out)), err)
	}
	slog.Info("ip_blocked", "ip", ip, "rule", ruleName)
	return ruleName, nil
}

// UnblockIP deletes the firewall rule created by BlockIP.
// handle is the rule name returned by BlockIP.
func UnblockIP(ip, handle string) error {
	ruleName := handle
	if ruleName == "" {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			return fmt.Errorf("unblock_ip: invalid IP: %s", ip)
		}
		ruleName = ruleNamePrefix + parsed.String()
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ruleName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("unblock_ip: netsh: %s: %w", strings.TrimSpace(string(out)), err)
	}
	slog.Info("ip_unblocked", "ip", ip, "rule", ruleName)
	return nil
}

// KillProcess terminates the process identified by pid after verifying its
// image name matches expectedProcessName.
func KillProcess(pid int, expectedProcessName string) error {
	if pid < 2 {
		return fmt.Errorf("kill_process: refusing to kill system process (pid %d)", pid)
	}

	// Verify image name via Toolhelp32Snapshot before killing.
	actual, err := processImageName(pid)
	if err != nil {
		return fmt.Errorf("kill_process: get image name for pid %d: %w", pid, err)
	}

	expected := filepath.Base(expectedProcessName)
	if !strings.EqualFold(filepath.Base(actual), expected) {
		return fmt.Errorf("kill_process: pid %d is %q, expected %q — refusing to kill", pid, actual, expected)
	}

	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("kill_process: OpenProcess pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("kill_process: TerminateProcess pid %d: %w", pid, err)
	}
	slog.Info("process_killed", "pid", pid, "name", actual)
	return nil
}

// QuarantineFile moves path to quarantineDir and denies all access via icacls.
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

	// Deny all access so the file cannot be read or executed.
	exec.Command("icacls", dst, "/deny", `Everyone:(F)`).Run() //nolint:errcheck
	slog.Info("file_quarantined", "original", path, "quarantine", dst)
	return dst, nil
}

// RestoreFile moves a quarantined file back to its original location.
func RestoreFile(quarantinePath, originalPath string) error {
	// Remove deny ACE before restoring.
	exec.Command("icacls", quarantinePath, "/remove:d", "Everyone").Run() //nolint:errcheck

	cleanedPath := filepath.Clean(originalPath)
	if !isAllowedPath(cleanedPath) {
		return fmt.Errorf("restore: path rejected: %s", originalPath)
	}

	if err := os.Rename(quarantinePath, cleanedPath); err != nil {
		return fmt.Errorf("restore: move %q → %q: %w", quarantinePath, cleanedPath, err)
	}
	slog.Info("file_restored", "path", cleanedPath)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

// processEntry32W mirrors PROCESSENTRY32W.
type processEntry32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [windows.MAX_PATH]uint16
}

var (
	procCreateToolhelp32Snapshot2 = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW2          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW2           = modkernel32.NewProc("Process32NextW")
)

const th32csSnapprocess = 0x00000002

// processImageName returns the executable name of the given PID.
func processImageName(pid int) (string, error) {
	h, _, err := procCreateToolhelp32Snapshot2.Call(th32csSnapprocess, 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return "", err
	}
	defer windows.CloseHandle(windows.Handle(h))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32FirstW2.Call(h, uintptr(unsafe.Pointer(&entry)))
	for r != 0 {
		if int(entry.ProcessID) == pid {
			return windows.UTF16ToString(entry.ExeFile[:]), nil
		}
		r, _, _ = procProcess32NextW2.Call(h, uintptr(unsafe.Pointer(&entry)))
	}
	return "", fmt.Errorf("pid %d not found in snapshot", pid)
}

// validateIP parses and canonicalises an IP address string using net.ParseIP,
// matching the Linux implementation and rejecting out-of-range octets.
func validateIP(ip string) (string, error) {
	ip = strings.TrimSpace(ip)
	if strings.Contains(ip, "/") {
		return "", fmt.Errorf("block_ip: CIDR ranges not accepted: %s", ip)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("block_ip: invalid IP: %s", ip)
	}
	return parsed.String(), nil
}
