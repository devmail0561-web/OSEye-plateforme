//go:build linux

// Linux implementation of Collect() using /proc and /proc/net/tcp.
package snapshot

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	_maxProcesses   = 5000
	_maxCmdlineBytes = 4096
)

var _secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(--password=|--passwd=|-p\s+|--token=|--secret=|--key=)\S+`),
	regexp.MustCompile(`(?i)(Bearer\s+|Basic\s+|token[=:\s]+)\S+`),
}

// Collect reads the current system state from /proc and returns a snapshot.
func Collect(agentID string, caseID string) (*AgentSnapshot, error) {
	snap := newSnapshot(agentID, caseID)

	procs, err := collectProcesses()
	if err != nil {
		slog.Warn("snapshot_proc_error", "err", err)
	}
	snap.Processes = procs

	conns, err := collectConnections()
	if err != nil {
		slog.Warn("snapshot_net_error", "err", err)
	}
	snap.Connections = conns

	return snap, nil
}

func collectProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("readdir /proc: %w", err)
	}
	var procs []ProcessInfo
	for _, e := range entries {
		if len(procs) >= _maxProcesses {
			slog.Warn("snapshot_proc_cap_reached", "cap", _maxProcesses)
			break
		}
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := readProcess(pid)
		if err != nil {
			continue
		}
		procs = append(procs, p)
	}
	return procs, nil
}

func readProcess(pid int) (ProcessInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)
	status, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return ProcessInfo{}, err
	}
	p := ProcessInfo{PID: pid}
	for _, line := range strings.Split(string(status), "\n") {
		parts := strings.SplitN(line, ":\t", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		switch parts[0] {
		case "Name":
			p.Name = val
		case "PPid":
			p.PPID, _ = strconv.Atoi(val)
		case "Uid":
			if fields := strings.Fields(val); len(fields) > 0 {
				p.UID, _ = strconv.Atoi(fields[0])
			}
		case "State":
			p.Status = stateDesc(val)
		}
	}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.Exe = exe
	}
	if cmdRaw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		if len(cmdRaw) > _maxCmdlineBytes {
			cmdRaw = cmdRaw[:_maxCmdlineBytes]
		}
		cmdline := strings.ReplaceAll(string(cmdRaw), "\x00", " ")
		p.Cmdline = maskSecrets(strings.TrimSpace(cmdline))
	}
	return p, nil
}

func maskSecrets(s string) string {
	for _, re := range _secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			idx := strings.IndexAny(m, "= ")
			if idx < 0 {
				return "[REDACTED]"
			}
			return m[:idx+1] + "[REDACTED]"
		})
	}
	return s
}

func stateDesc(s string) string {
	if len(s) == 0 {
		return "unknown"
	}
	switch s[0] {
	case 'R':
		return "running"
	case 'S':
		return "sleeping"
	case 'D':
		return "disk_sleep"
	case 'Z':
		return "zombie"
	case 'T':
		return "stopped"
	case 'I':
		return "idle"
	default:
		return "unknown"
	}
}

func collectConnections() ([]ConnectionInfo, error) {
	inodeMap := buildInodeMap()
	var all []ConnectionInfo
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		conns, err := parseProcNetTCP(path, inodeMap)
		if err != nil {
			continue
		}
		all = append(all, conns...)
	}
	return all, nil
}

func buildInodeMap() map[int]int {
	m := make(map[int]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil {
				continue
			}
			var inode int
			if _, err := fmt.Sscanf(link, "socket:[%d]", &inode); err == nil {
				m[inode] = pid
			}
		}
	}
	return m
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

func parseProcNetTCP(path string, inodeMap map[int]int) ([]ConnectionInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	is6 := strings.Contains(path, "tcp6")
	var conns []ConnectionInfo
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, err := parseHexAddr(fields[1], is6)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddr(fields[2], is6)
		if err != nil {
			continue
		}
		stateHex := strings.ToUpper(fields[3])
		state := tcpStates[stateHex]
		if state == "" {
			state = stateHex
		}
		inode, _ := strconv.Atoi(fields[9])
		conns = append(conns, ConnectionInfo{
			Proto:      "tcp",
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			PID:        inodeMap[inode],
		})
	}
	return conns, nil
}

func parseHexAddr(s string, is6 bool) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr %q", s)
	}
	portNum, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}
	b, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	expectedLen := 4
	if is6 {
		expectedLen = 16
	}
	if len(b) != expectedLen {
		return "", 0, fmt.Errorf("addr %q: expected %d bytes, got %d", s, expectedLen, len(b))
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	var ip net.IP
	if is6 {
		ip = net.IP(b)
	} else {
		ip = net.IPv4(b[0], b[1], b[2], b[3])
	}
	return ip.String(), int(portNum), nil
}
