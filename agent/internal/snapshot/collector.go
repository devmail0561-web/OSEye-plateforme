// Package snapshot collects a point-in-time system image (processes + network
// connections) and posts it to the OSEye server via mTLS HTTP.
// Platform-specific Collect() implementations live in collector_linux.go,
// collector_windows.go, and collector_darwin.go.
package snapshot

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

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

// newSnapshot returns an AgentSnapshot with the common metadata filled in.
// Platform-specific Collect() functions call this before populating procs/conns.
func newSnapshot(agentID, caseID string) *AgentSnapshot {
	hostname, _ := os.Hostname()
	return &AgentSnapshot{
		SnapshotID: uuid.New().String(),
		AgentID:    agentID,
		Hostname:   hostname,
		TakenAt:    time.Now().UTC(),
		CaseID:     caseID,
	}
}

// Post serialises snap and POSTs it to apiURL/api/v1/snapshots using mTLS.
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
