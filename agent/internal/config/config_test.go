package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_defaults(t *testing.T) {
	vars := []string{
		"OSEYE_GRPC_ADDR", "OSEYE_TLS_CERT", "OSEYE_TLS_KEY", "OSEYE_TLS_CA",
		"OSEYE_BUFFER_PATH", "OSEYE_AGENT_ID", "OSEYE_BATCH_SIZE",
		"OSEYE_BATCH_TIMEOUT_MS", "OSEYE_MAX_CPU_PCT", "OSEYE_MAX_MEM_MB",
		"OSEYE_INOTIFY_WATCHES", "OSEYE_FANOTIFY_PATHS",
		"OSEYE_ED25519_SIGNING_KEY", "OSEYE_QUARANTINE_DIR",
		"OSEYE_SYSLOG_ADDR", "OSEYE_ENROLL_URL",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GRPCAddr != "localhost:50051" {
		t.Errorf("GRPCAddr = %q, want localhost:50051", cfg.GRPCAddr)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d, want 1000", cfg.BatchSize)
	}
	if cfg.BatchTimeout != 1000*time.Millisecond {
		t.Errorf("BatchTimeout = %v, want 1s", cfg.BatchTimeout)
	}
	if cfg.MaxCPUPct != 4.0 {
		t.Errorf("MaxCPUPct = %f, want 4.0", cfg.MaxCPUPct)
	}
	if cfg.MaxMemMB != 256 {
		t.Errorf("MaxMemMB = %d, want 256", cfg.MaxMemMB)
	}
}

func TestLoad_envOverride(t *testing.T) {
	t.Setenv("OSEYE_GRPC_ADDR", "server:9000")
	t.Setenv("OSEYE_BATCH_SIZE", "500")
	t.Setenv("OSEYE_BATCH_TIMEOUT_MS", "200")
	t.Setenv("OSEYE_MAX_CPU_PCT", "2.5")
	t.Setenv("OSEYE_MAX_MEM_MB", "128")
	t.Setenv("OSEYE_AGENT_ID", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GRPCAddr != "server:9000" {
		t.Errorf("GRPCAddr = %q, want server:9000", cfg.GRPCAddr)
	}
	if cfg.BatchSize != 500 {
		t.Errorf("BatchSize = %d, want 500", cfg.BatchSize)
	}
	if cfg.BatchTimeout != 200*time.Millisecond {
		t.Errorf("BatchTimeout = %v, want 200ms", cfg.BatchTimeout)
	}
	if cfg.MaxCPUPct != 2.5 {
		t.Errorf("MaxCPUPct = %f, want 2.5", cfg.MaxCPUPct)
	}
	if cfg.MaxMemMB != 128 {
		t.Errorf("MaxMemMB = %d, want 128", cfg.MaxMemMB)
	}
	if cfg.AgentID != "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Errorf("AgentID = %q, want a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", cfg.AgentID)
	}
}

func TestLoad_invalidIntReturnsError(t *testing.T) {
	t.Setenv("OSEYE_BATCH_SIZE", "not-a-number")
	_, err := Load()
	if err == nil {
		t.Error("expected error for non-numeric OSEYE_BATCH_SIZE")
	}
}

func TestLoad_invalidFloatReturnsError(t *testing.T) {
	t.Setenv("OSEYE_MAX_CPU_PCT", "bad-float")
	_, err := Load()
	if err == nil {
		t.Error("expected error for non-numeric OSEYE_MAX_CPU_PCT")
	}
}

func TestValidate_GRPCAddrNotHostPort(t *testing.T) {
	cfg := validConfig()
	cfg.GRPCAddr = "no-port-here"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for GRPCAddr without port")
	}
}

func TestValidate_GRPCAddrNonNumericPort(t *testing.T) {
	cfg := validConfig()
	cfg.GRPCAddr = "localhost:abc"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for GRPCAddr with non-numeric port")
	}
}

func TestValidate_GRPCAddrPortOutOfRange(t *testing.T) {
	cfg := validConfig()
	cfg.GRPCAddr = "localhost:99999"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for GRPCAddr with port > 65535")
	}
}

func TestValidate_SyslogAddrInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.SyslogAddr = "not-valid"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid SyslogAddr")
	}
}

func TestValidate_MaxCPUPctOver100(t *testing.T) {
	cfg := validConfig()
	cfg.MaxCPUPct = 150
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for MaxCPUPct > 100")
	}
}

func TestValidate_MaxMemMBZero(t *testing.T) {
	cfg := validConfig()
	cfg.MaxMemMB = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for MaxMemMB = 0")
	}
}

func TestValidate_BatchSizeTooLarge(t *testing.T) {
	cfg := validConfig()
	cfg.BatchSize = 200_000
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for BatchSize > 100000")
	}
}

func TestValidate_AgentIDInvalidUUID(t *testing.T) {
	cfg := validConfig()
	cfg.AgentID = "not-a-uuid"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid AgentID")
	}
}

func TestValidate_AgentIDEmpty_OK(t *testing.T) {
	cfg := validConfig()
	cfg.AgentID = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty AgentID should be valid, got: %v", err)
	}
}

func TestValidate_BufferPathEmpty(t *testing.T) {
	cfg := validConfig()
	cfg.BufferPath = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty BufferPath")
	}
}

func TestValidate_BufferPathRelative(t *testing.T) {
	cfg := validConfig()
	cfg.BufferPath = "relative/path.db"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative BufferPath")
	}
}

func TestValidate_TLSCertRelative(t *testing.T) {
	cfg := validConfig()
	cfg.TLSCertFile = "certs/agent.crt"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative TLSCertFile")
	}
}

func TestValidate_QuarantineDirEmpty(t *testing.T) {
	cfg := validConfig()
	cfg.QuarantineDir = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty QuarantineDir")
	}
}

func TestValidate_QuarantineDirCritical(t *testing.T) {
	cfg := validConfig()
	cfg.QuarantineDir = "/"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for QuarantineDir = /")
	}
}

func TestValidate_FanotifyPathRelative(t *testing.T) {
	cfg := validConfig()
	cfg.FanotifyPaths = []string{"relative/path"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative FanotifyPaths entry")
	}
}

func TestValidate_InotifyWatchEmptyPath(t *testing.T) {
	cfg := validConfig()
	cfg.InotifyWatches = []InotifyWatch{{Path: "", Recursive: false, Mask: 0xFFF}}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for InotifyWatch with empty path")
	}
}

func TestValidate_InotifyWatchRelativePath(t *testing.T) {
	cfg := validConfig()
	cfg.InotifyWatches = []InotifyWatch{{Path: "tmp", Recursive: false, Mask: 0xFFF}}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for InotifyWatch with relative path")
	}
}

func TestValidate_EnrollURLInvalidScheme(t *testing.T) {
	cfg := validConfig()
	cfg.EnrollServerURL = "ftp://example.com/enroll"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for EnrollServerURL with ftp scheme")
	}
}

func TestValidate_EnrollURLValid(t *testing.T) {
	cfg := validConfig()
	cfg.EnrollServerURL = "https://enroll.example.com/api/v1/enroll"
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid EnrollServerURL rejected: %v", err)
	}
}

func TestParseInotifyWatches_InvalidJSON(t *testing.T) {
	_, err := parseInotifyWatches("not json at all")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoad_InvalidInotifyJSON(t *testing.T) {
	t.Setenv("OSEYE_INOTIFY_WATCHES", "{bad json}")
	_, err := Load()
	if err == nil {
		t.Error("expected error for invalid OSEYE_INOTIFY_WATCHES JSON")
	}
}

func validConfig() *Config {
	return &Config{
		GRPCAddr:       "localhost:50051",
		TLSCertFile:    "/etc/oseye/certs/agent.crt",
		TLSKeyFile:     "/etc/oseye/certs/agent.key",
		CACertFile:     "/etc/oseye/certs/ca.crt",
		Ed25519KeyFile: "/etc/oseye/certs/agent.ed25519.key",
		BufferPath:     "/var/lib/oseye/buffer.db",
		BatchSize:      1000,
		BatchTimeout:   time.Second,
		MaxCPUPct:      4.0,
		MaxMemMB:       256,
		QuarantineDir:  "/var/lib/oseye/quarantine",
		SyslogAddr:     "127.0.0.1:514",
	}
}
