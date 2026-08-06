package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_defaults(t *testing.T) {
	// Unset any env vars that might be set in the environment
	vars := []string{
		"OSEYE_GRPC_ADDR", "OSEYE_TLS_CERT", "OSEYE_TLS_KEY", "OSEYE_TLS_CA",
		"OSEYE_BUFFER_PATH", "OSEYE_AGENT_ID", "OSEYE_BATCH_SIZE",
		"OSEYE_BATCH_TIMEOUT_MS", "OSEYE_MAX_CPU_PCT", "OSEYE_MAX_MEM_MB",
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
	t.Setenv("OSEYE_AGENT_ID", "test-agent-001")

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
	if cfg.AgentID != "test-agent-001" {
		t.Errorf("AgentID = %q, want test-agent-001", cfg.AgentID)
	}
}

func TestLoad_invalidEnvFallsBackToDefault(t *testing.T) {
	t.Setenv("OSEYE_BATCH_SIZE", "not-a-number")
	t.Setenv("OSEYE_MAX_CPU_PCT", "bad-float")
	t.Setenv("OSEYE_MAX_MEM_MB", "??")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.BatchSize != 1000 {
		t.Errorf("BatchSize = %d, want fallback 1000", cfg.BatchSize)
	}
	if cfg.MaxCPUPct != 4.0 {
		t.Errorf("MaxCPUPct = %f, want fallback 4.0", cfg.MaxCPUPct)
	}
	if cfg.MaxMemMB != 256 {
		t.Errorf("MaxMemMB = %d, want fallback 256", cfg.MaxMemMB)
	}
}
