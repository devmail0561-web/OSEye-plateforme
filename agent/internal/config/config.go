package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the agent runtime configuration.
// Values are loaded from environment variables; no config file required.
type Config struct {
	// gRPC server address (host:port)
	GRPCAddr string

	// mTLS certificate paths
	TLSCertFile string
	TLSKeyFile  string
	CACertFile  string

	// Ed25519 signing key for batch integrity (separate from the mTLS key)
	Ed25519KeyFile string

	// Local offline buffer
	BufferPath string

	// Batch settings
	BatchSize    int
	BatchTimeout time.Duration

	// Agent identity
	AgentID string

	// Resource watchdog thresholds
	MaxCPUPct float64
	MaxMemMB  int

	// Collectors configuration
	FanotifyPaths  []string
	InotifyWatches []InotifyWatch

	// Phase 2 collectors
	JournaldPriority string
	JournaldUnits    []string
	SyslogAddr       string

	// Response engine
	QuarantineDir string // OSEYE_QUARANTINE_DIR, default /var/lib/oseye/quarantine

	// Enrollment — used only at first boot when TLSCertFile does not exist yet
	EnrollServerURL string // OSEYE_ENROLL_URL,   default ""
	EnrollToken     string // OSEYE_ENROLL_TOKEN, default ""
}

// InotifyWatch represents an inotify watch configuration.
type InotifyWatch struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Mask      uint32 `json:"mask"`
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		GRPCAddr:     getenv("OSEYE_GRPC_ADDR", "localhost:50051"),
		TLSCertFile:    getenv("OSEYE_TLS_CERT", "/etc/oseye/certs/agent.crt"),
		TLSKeyFile:     getenv("OSEYE_TLS_KEY", "/etc/oseye/certs/agent.key"),
		CACertFile:     getenv("OSEYE_TLS_CA", "/etc/oseye/certs/ca.crt"),
		Ed25519KeyFile: getenv("OSEYE_ED25519_SIGNING_KEY", "/etc/oseye/certs/agent.ed25519.key"),
		BufferPath:   getenv("OSEYE_BUFFER_PATH", "/var/lib/oseye/buffer.db"),
		AgentID:      getenv("OSEYE_AGENT_ID", ""),
		BatchSize:    getenvInt("OSEYE_BATCH_SIZE", 1000),
		BatchTimeout: getenvDuration("OSEYE_BATCH_TIMEOUT_MS", 1000),
		MaxCPUPct:    getenvFloat("OSEYE_MAX_CPU_PCT", 4.0),
		MaxMemMB:     getenvInt("OSEYE_MAX_MEM_MB", 256),
		FanotifyPaths: parseFanotifyPaths(
			getenv("OSEYE_FANOTIFY_PATHS", "/etc/passwd,/etc/shadow,/root/.ssh"),
		),
		InotifyWatches: parseInotifyWatches(
			getenv("OSEYE_INOTIFY_WATCHES", `[{"path":"/tmp","recursive":false,"mask":4095}]`),
		),
		JournaldPriority: getenv("OSEYE_JOURNALD_PRIORITY", ""),
		JournaldUnits: parseCSV(
			getenv("OSEYE_JOURNALD_UNITS", ""),
		),
		SyslogAddr:    getenv("OSEYE_SYSLOG_ADDR", "127.0.0.1:514"),
		QuarantineDir:   getenv("OSEYE_QUARANTINE_DIR", "/var/lib/oseye/quarantine"),
		EnrollServerURL: getenv("OSEYE_ENROLL_URL", ""),
		EnrollToken:     getenv("OSEYE_ENROLL_TOKEN", ""),
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks that required configuration fields have valid values.
func (c *Config) Validate() error {
	if c.BatchSize <= 0 {
		return fmt.Errorf("config: BatchSize must be > 0, got %d", c.BatchSize)
	}
	if c.BatchTimeout <= 0 {
		return fmt.Errorf("config: BatchTimeout must be > 0, got %s", c.BatchTimeout)
	}
	if c.MaxCPUPct < 0 {
		return fmt.Errorf("config: MaxCPUPct must be >= 0, got %f", c.MaxCPUPct)
	}
	if c.GRPCAddr == "" {
		return fmt.Errorf("config: GRPCAddr must not be empty")
	}
	return nil
}

func parseCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseFanotifyPaths(pathsStr string) []string {
	if pathsStr == "" {
		return []string{}
	}
	paths := strings.Split(pathsStr, ",")
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseInotifyWatches(watchesJSON string) []InotifyWatch {
	if watchesJSON == "" {
		return []InotifyWatch{}
	}
	var watches []InotifyWatch
	if err := json.Unmarshal([]byte(watchesJSON), &watches); err != nil {
		slog.Warn("failed to parse OSEYE_INOTIFY_WATCHES, using default",
			slog.String("error", err.Error()),
			slog.String("input", watchesJSON))
		return []InotifyWatch{
			{Path: "/tmp", Recursive: false, Mask: uint32(0xFFF)}, // linux IN_ALL_EVENTS
		}
	}
	return watches
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func getenvDuration(key string, fallbackMs int) time.Duration {
	ms := getenvInt(key, fallbackMs)
	return time.Duration(ms) * time.Millisecond
}
