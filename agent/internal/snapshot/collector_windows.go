//go:build windows

// Windows implementation of Collect() using Toolhelp32 + netstat.
package snapshot

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Collect gathers a process + network snapshot on Windows.
func Collect(agentID string, caseID string) (*AgentSnapshot, error) {
	snap := newSnapshot(agentID, caseID)

	procs, err := collectProcessesWin()
	if err != nil {
		slog.Warn("snapshot_proc_error", "err", err)
	}
	snap.Processes = procs

	conns, err := collectConnectionsWin()
	if err != nil {
		slog.Warn("snapshot_net_error", "err", err)
	}
	snap.Connections = conns

	return snap, nil
}

// ── process collection (Toolhelp32) ──────────────────────────────────────────

type processEntry32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [windows.MAX_PATH]uint16
}

var (
	modkernel32w                  = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32SnapshotW = modkernel32w.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstWw          = modkernel32w.NewProc("Process32FirstW")
	procProcess32NextWw           = modkernel32w.NewProc("Process32NextW")
)

const th32csSnapprocessW = 0x00000002

func collectProcessesWin() ([]ProcessInfo, error) {
	h, _, err := procCreateToolhelp32SnapshotW.Call(th32csSnapprocessW, 0)
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(h))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32FirstWw.Call(h, uintptr(unsafe.Pointer(&entry)))
	var procs []ProcessInfo
	for r != 0 {
		procs = append(procs, ProcessInfo{
			PID:  int(entry.ProcessID),
			PPID: int(entry.ParentProcessID),
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		r, _, _ = procProcess32NextWw.Call(h, uintptr(unsafe.Pointer(&entry)))
	}
	return procs, nil
}

// ── network collection (netstat) ──────────────────────────────────────────────

func collectConnectionsWin() ([]ConnectionInfo, error) {
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		return nil, err
	}
	var conns []ConnectionInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(strings.ToUpper(line), "TCP") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := splitWinAddr(fields[1])
		remote := splitWinAddr(fields[2])
		pid, _ := strconv.Atoi(fields[4])
		conns = append(conns, ConnectionInfo{
			Proto:      "tcp",
			LocalAddr:  local[0],
			LocalPort:  portNum(local[1]),
			RemoteAddr: remote[0],
			RemotePort: portNum(remote[1]),
			State:      fields[3],
			PID:        pid,
		})
	}
	return conns, nil
}

func splitWinAddr(s string) [2]string {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return [2]string{s, "0"}
	}
	return [2]string{s[:idx], s[idx+1:]}
}

func portNum(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
