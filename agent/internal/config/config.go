package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const maxBatchSize = 100_000

// Config holds the agent runtime configuration.
// Values are loaded from environment variables; no config file required.
type Config struct {
	GRPCAddr string

	TLSCertFile    string
	TLSKeyFile     string
	CACertFile     string
	Ed25519KeyFile string

	BufferPath string

	BatchSize    int
	BatchTimeout time.Duration

	AgentID string

	MaxCPUPct float64
	MaxMemMB  int

	FanotifyPaths  []string
	InotifyWatches []InotifyWatch

	JournaldPriority string
	JournaldUnits    []string
	SyslogAddr       string

	QuarantineDir string

	EnrollServerURL string
	EnrollToken     string

	// APIAddr is the base URL of the OSEye REST API (for snapshot POST).
	// Defaults to empty; when empty, the snapshot collector skips the POST.
	APIAddr string
}

// InotifyWatch represents an inotify watch configuration.
type InotifyWatch struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Mask      uint32 `json:"mask"`
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	inotifyWatches, err := parseInotifyWatches(
		getenv("OSEYE_INOTIFY_WATCHES", `[{"path":"/tmp","recursive":false,"mask":4095}]`),
	)
	if err != nil {
		return nil, err
	}

	batchSize, err := getenvIntStrict("OSEYE_BATCH_SIZE", 1000)
	if err != nil {
		return nil, err
	}
	maxCPU, err := getenvFloatStrict("OSEYE_MAX_CPU_PCT", 4.0)
	if err != nil {
		return nil, err
	}
	maxMem, err := getenvIntStrict("OSEYE_MAX_MEM_MB", 256)
	if err != nil {
		return nil, err
	}
	batchTimeoutMs, err := getenvIntStrict("OSEYE_BATCH_TIMEOUT_MS", 1000)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		GRPCAddr:       getenv("OSEYE_GRPC_ADDR", "localhost:50051"),
		TLSCertFile:    getenv("OSEYE_TLS_CERT", "/etc/oseye/certs/agent.crt"),
		TLSKeyFile:     getenv("OSEYE_TLS_KEY", "/etc/oseye/certs/agent.key"),
		CACertFile:     getenv("OSEYE_TLS_CA", "/etc/oseye/certs/ca.crt"),
		Ed25519KeyFile: getenv("OSEYE_ED25519_SIGNING_KEY", "/etc/oseye/certs/agent.ed25519.key"),
		BufferPath:     getenv("OSEYE_BUFFER_PATH", "/var/lib/oseye/buffer.db"),
		AgentID:        getenv("OSEYE_AGENT_ID", ""),
		BatchSize:      batchSize,
		BatchTimeout:   time.Duration(batchTimeoutMs) * time.Millisecond,
		MaxCPUPct:      maxCPU,
		MaxMemMB:       maxMem,
		FanotifyPaths: parseFanotifyPaths(
			getenv("OSEYE_FANOTIFY_PATHS", "/etc/passwd,/etc/shadow,/root/.ssh"),
		),
		InotifyWatches:   inotifyWatches,
		JournaldPriority: getenv("OSEYE_JOURNALD_PRIORITY", ""),
		JournaldUnits: parseCSV(
			getenv("OSEYE_JOURNALD_UNITS", ""),
		),
		SyslogAddr:      getenv("OSEYE_SYSLOG_ADDR", "127.0.0.1:514"),
		QuarantineDir:   getenv("OSEYE_QUARANTINE_DIR", "/var/lib/oseye/quarantine"),
		EnrollServerURL: getenv("OSEYE_ENROLL_URL", ""),
		APIAddr:         getenv("OSEYE_API_ADDR", ""),
		EnrollToken:     getenv("OSEYE_ENROLL_TOKEN", ""),
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks that required configuration fields have valid values.
func (c *Config) Validate() error {
	// --- GRPCAddr: must be valid host:port with numeric port in [1,65535] ---
	if c.GRPCAddr == "" {
		return fmt.Errorf("config: GRPCAddr must not be empty")
	}
	if _, portStr, err := net.SplitHostPort(c.GRPCAddr); err != nil {
		return fmt.Errorf("config: GRPCAddr must be host:port, got %q: %w", c.GRPCAddr, err)
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("config: GRPCAddr port must be 1-65535, got %q", portStr)
		}
	}

	// --- SyslogAddr: same host:port validation ---
	if c.SyslogAddr != "" {
		if _, portStr, err := net.SplitHostPort(c.SyslogAddr); err != nil {
			return fmt.Errorf("config: SyslogAddr must be host:port, got %q: %w", c.SyslogAddr, err)
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("config: SyslogAddr port must be 1-65535, got %q", portStr)
			}
		}
	}

	// --- Batch settings ---
	if c.BatchSize <= 0 || c.BatchSize > maxBatchSize {
		return fmt.Errorf("config: BatchSize must be in [1, %d], got %d", maxBatchSize, c.BatchSize)
	}
	if c.BatchTimeout <= 0 {
		return fmt.Errorf("config: BatchTimeout must be > 0, got %s", c.BatchTimeout)
	}

	// --- Resource limits ---
	if c.MaxCPUPct < 0 || c.MaxCPUPct > 100 {
		return fmt.Errorf("config: MaxCPUPct must be in [0, 100], got %f", c.MaxCPUPct)
	}
	if c.MaxMemMB <= 0 {
		return fmt.Errorf("config: MaxMemMB must be > 0, got %d", c.MaxMemMB)
	}

	// --- AgentID: if set, must be UUID v4 ---
	if c.AgentID != "" && !uuidV4Re.MatchString(strings.ToLower(c.AgentID)) {
		return fmt.Errorf("config: AgentID must be a valid UUID v4, got %q", c.AgentID)
	}

	// --- Paths: must be absolute ---
	if c.BufferPath == "" {
		return fmt.Errorf("config: BufferPath must not be empty")
	}
	if err := requireAbsolutePath("BufferPath", c.BufferPath); err != nil {
		return err
	}
	if err := requireAbsolutePath("TLSCertFile", c.TLSCertFile); err != nil {
		return err
	}
	if err := requireAbsolutePath("TLSKeyFile", c.TLSKeyFile); err != nil {
		return err
	}
	if err := requireAbsolutePath("CACertFile", c.CACertFile); err != nil {
		return err
	}
	if c.Ed25519KeyFile != "" {
		if err := requireAbsolutePath("Ed25519KeyFile", c.Ed25519KeyFile); err != nil {
			return err
		}
	}

	// --- QuarantineDir: absolute, not a critical system directory ---
	if c.QuarantineDir == "" {
		return fmt.Errorf("config: QuarantineDir must not be empty")
	}
	if err := requireAbsolutePath("QuarantineDir", c.QuarantineDir); err != nil {
		return err
	}
	if err := rejectCriticalPath("QuarantineDir", c.QuarantineDir); err != nil {
		return err
	}

	// --- FanotifyPaths: absolute ---
	for i, p := range c.FanotifyPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("config: FanotifyPaths[%d] must be absolute, got %q", i, p)
		}
	}

	// --- InotifyWatches: non-empty absolute paths ---
	for i, w := range c.InotifyWatches {
		if w.Path == "" {
			return fmt.Errorf("config: InotifyWatches[%d].Path must not be empty", i)
		}
		if !filepath.IsAbs(w.Path) {
			return fmt.Errorf("config: InotifyWatches[%d].Path must be absolute, got %q", i, w.Path)
		}
	}

	// --- EnrollServerURL: if set, must be valid HTTPS URL ---
	if c.EnrollServerURL != "" {
		u, err := url.Parse(c.EnrollServerURL)
		if err != nil {
			return fmt.Errorf("config: EnrollServerURL invalid URL: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("config: EnrollServerURL scheme must be https, got %q", u.Scheme)
		}
		if u.Scheme == "http" {
			slog.Warn("EnrollServerURL uses plain HTTP — communications will not be encrypted; set OSEYE_INSECURE=true is implicit", "url", c.EnrollServerURL)
		}
		if u.Host == "" {
			return fmt.Errorf("config: EnrollServerURL missing host")
		}
	}

	return nil
}

func requireAbsolutePath(field, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("config: %s must be an absolute path, got %q", field, path)
	}
	return nil
}

// CORE-007: /proc/self and /proc/1 are added explicitly so that a QuarantineDir
// targeting these symlink-heavy pseudo-directories is also rejected.
var criticalPaths = []string{"/", "/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys", "/proc/self", "/proc/1"}

func rejectCriticalPath(field, path string) error {
	cleaned := filepath.Clean(path)
	for _, cp := range criticalPaths {
		if cleaned == cp {
			return fmt.Errorf("config: %s must not be a critical system path (%s)", field, cp)
		}
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

func parseInotifyWatches(watchesJSON string) ([]InotifyWatch, error) {
	if watchesJSON == "" {
		return []InotifyWatch{}, nil
	}
	var watches []InotifyWatch
	if err := json.Unmarshal([]byte(watchesJSON), &watches); err != nil {
		return nil, fmt.Errorf("config: OSEYE_INOTIFY_WATCHES invalid JSON: %w", err)
	}
	return watches, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getenvIntStrict returns an error if the env var is set but not a valid integer.
func getenvIntStrict(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, v)
	}
	return n, nil
}

// getenvFloatStrict returns an error if the env var is set but not a valid float.
func getenvFloatStrict(key string, fallback float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a number, got %q", key, v)
	}
	return f, nil
}
