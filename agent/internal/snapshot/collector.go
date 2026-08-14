//go:build linux

// Package snapshot collects a point-in-time system image (processes + network
// connections) from the Linux proc filesystem and posts it to the OSEye server.
package snapshot

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// _maxProcesses caps the process list to avoid unbounded memory on busy hosts.
	_maxProcesses = 5000
	// _maxCmdlineBytes caps cmdline length; CLI args can contain secrets.
	_maxCmdlineBytes = 4096
)

// _secretPatterns masks common secret patterns in cmdline strings.
// Patterns: --password=X, -p X, --token=X, Authorization: Bearer X, etc.
var _secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(--password=|--passwd=|-p\s+|--token=|--secret=|--key=)\S+`),
	regexp.MustCompile(`(?i)(Bearer\s+|Basic\s+|token[=:\s]+)\S+`),
}

// ProcessInfo mirrors the server-side schema.ProcessInfo.
type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	UID     int    `json:"uid"`
	Status  string `json:"status"`
}

// ConnectionInfo mirrors the server-side schema.ConnectionInfo.
type ConnectionInfo struct {
	Proto      string `json:"proto"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
}

// AgentSnapshot is the payload POSTed to /api/v1/snapshots.
type AgentSnapshot struct {
	SnapshotID  string           `json:"snapshot_id"`
	AgentID     string           `json:"agent_id"`
	Hostname    string           `json:"hostname"`
	TakenAt     time.Time        `json:"taken_at"`
	Processes   []ProcessInfo    `json:"processes"`
	Connections []ConnectionInfo `json:"connections"`
	CaseID      string           `json:"case_id,omitempty"`
}

// TLSConfig holds the mTLS credentials for the snapshot HTTP client.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Collect reads the current system state from /proc and returns a snapshot.
func Collect(agentID string, caseID string) (*AgentSnapshot, error) {
	hostname, _ := os.Hostname()

	procs, err := collectProcesses()
	if err != nil {
		slog.Warn("snapshot_proc_error", "err", err)
		procs = nil
	}

	conns, err := collectConnections()
	if err != nil {
		slog.Warn("snapshot_net_error", "err", err)
		conns = nil
	}

	return &AgentSnapshot{
		SnapshotID:  uuid.New().String(),
		AgentID:     agentID,
		Hostname:    hostname,
		TakenAt:     time.Now().UTC(),
		Processes:   procs,
		Connections: conns,
		CaseID:      caseID,
	}, nil
}

// Post serialises snap and POSTs it to apiURL + "/api/v1/snapshots" using mTLS.
func Post(ctx context.Context, snap *AgentSnapshot, apiURL string, tlsCfg TLSConfig) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("snapshot: marshal: %w", err)
	}

	client, err := buildHTTPClient(tlsCfg)
	if err != nil {
		return fmt.Errorf("snapshot: tls client: %w", err)
	}

	url := strings.TrimRight(apiURL, "/") + "/api/v1/snapshots"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("snapshot: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("snapshot: post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("snapshot: server returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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
			continue // process may have exited
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
			fields := strings.Fields(val)
			if len(fields) > 0 {
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
		// Truncate before any string operations to bound memory.
		if len(cmdRaw) > _maxCmdlineBytes {
			cmdRaw = cmdRaw[:_maxCmdlineBytes]
		}
		cmdline := strings.ReplaceAll(string(cmdRaw), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		p.Cmdline = maskSecrets(cmdline)
	}

	return p, nil
}

// maskSecrets redacts common secret patterns from cmdline strings.
func maskSecrets(s string) string {
	for _, re := range _secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			// Keep the flag/prefix, replace the value with [REDACTED].
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

// collectConnections reads /proc/net/tcp and /proc/net/tcp6.
// It builds the inode→PID map once (O(N+M)) before parsing connections.
func collectConnections() ([]ConnectionInfo, error) {
	// Build inode→PID map once instead of O(N×M) per-connection lookups.
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

// buildInodeMap returns a map from socket inode → PID by scanning /proc/*/fd once.
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
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			var inode int
			if n, _ := fmt.Sscanf(link, "socket:[%d]", &inode); n == 1 && inode > 0 {
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
			continue // header or blank
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
		pid := inodeMap[inode] // O(1) lookup

		conns = append(conns, ConnectionInfo{
			Proto:      "tcp",
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			PID:        pid,
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

	// Validate length before indexing to prevent panic on malformed /proc/net/tcp.
	if is6 {
		if len(b) != 16 {
			return "", 0, fmt.Errorf("IPv6 addr must be 16 bytes, got %d", len(b))
		}
	} else {
		if len(b) != 4 {
			return "", 0, fmt.Errorf("IPv4 addr must be 4 bytes, got %d", len(b))
		}
	}

	// Reverse byte order (little-endian in /proc/net/tcp).
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

func buildHTTPClient(cfg TLSConfig) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert")
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}, nil
}
