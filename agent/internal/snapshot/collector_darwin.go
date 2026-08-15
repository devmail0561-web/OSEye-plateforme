//go:build darwin

// macOS implementation of Collect() using ps(1) + netstat(1).
package snapshot

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// Collect gathers a process + network snapshot on macOS.
func Collect(agentID string, caseID string) (*AgentSnapshot, error) {
	snap := newSnapshot(agentID, caseID)

	procs, err := collectProcessesDarwin()
	if err != nil {
		slog.Warn("snapshot_proc_error", "err", err)
	}
	snap.Processes = procs

	conns, err := collectConnectionsDarwin()
	if err != nil {
		slog.Warn("snapshot_net_error", "err", err)
	}
	snap.Connections = conns

	return snap, nil
}

func collectProcessesDarwin() ([]ProcessInfo, error) {
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,uid=,comm=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var procs []ProcessInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		uid, _ := strconv.Atoi(fields[2])
		name := strings.Join(fields[3:], " ")
		procs = append(procs, ProcessInfo{
			PID: pid, PPID: ppid, UID: uid, Name: name,
		})
	}
	return procs, nil
}

func collectConnectionsDarwin() ([]ConnectionInfo, error) {
	out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	var conns []ConnectionInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(strings.ToLower(line), "tcp") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		local := splitDarwinAddr(fields[3])
		remote := splitDarwinAddr(fields[4])
		conns = append(conns, ConnectionInfo{
			Proto:      fields[0],
			LocalAddr:  local[0],
			LocalPort:  darwinPort(local[1]),
			RemoteAddr: remote[0],
			RemotePort: darwinPort(remote[1]),
			State:      fields[5],
		})
	}
	return conns, nil
}

// splitDarwinAddr handles "1.2.3.4.5678" (macOS uses dots for port separator).
func splitDarwinAddr(s string) [2]string {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return [2]string{s, "0"}
	}
	return [2]string{s[:idx], s[idx+1:]}
}

func darwinPort(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
