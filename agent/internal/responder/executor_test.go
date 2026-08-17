//go:build linux

package responder_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/responder"
)

func TestQuarantineFile(t *testing.T) {
	tmp := t.TempDir()
	quarantineDir := filepath.Join(tmp, "quarantine")
	original := filepath.Join(tmp, "malicious.sh")

	if err := os.WriteFile(original, []byte("#!/bin/sh\nrm -rf /"), 0o755); err != nil {
		t.Fatal(err)
	}

	quarPath, err := responder.QuarantineFile(original, quarantineDir)
	if err != nil {
		t.Fatalf("QuarantineFile failed: %v", err)
	}

	// Original must be gone
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatal("original file should not exist after quarantine")
	}

	// Quarantined file must exist
	if _, err := os.Stat(quarPath); err != nil {
		t.Fatalf("quarantine file should exist at %s: %v", quarPath, err)
	}

	// Permissions should be 000
	info, err := os.Stat(quarPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0 {
		t.Fatalf("expected 000 permissions, got %o", info.Mode().Perm())
	}
}

func TestRestoreFile(t *testing.T) {
	tmp := t.TempDir()
	quarantineDir := filepath.Join(tmp, "quarantine")
	original := filepath.Join(tmp, "restore_me.txt")
	restoreDest := filepath.Join(tmp, "restored.txt")

	if err := os.WriteFile(original, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	quarPath, err := responder.QuarantineFile(original, quarantineDir)
	if err != nil {
		t.Fatalf("QuarantineFile failed: %v", err)
	}

	if err := responder.RestoreFile(quarPath, restoreDest); err != nil {
		t.Fatalf("RestoreFile failed: %v", err)
	}

	data, err := os.ReadFile(restoreDest)
	if err != nil {
		t.Fatalf("restored file not readable: %v", err)
	}
	if string(data) != "content" {
		t.Fatalf("restored content mismatch: %q", data)
	}
}

func TestKillProcessWrongName(t *testing.T) {
	// PID 1 (init/systemd) exists but its comm is never "malware".
	// KillProcess should refuse with a PID-reuse guard error.
	err := responder.KillProcess(1, "malware")
	if err == nil {
		t.Fatal("expected error for mismatched process name, got nil")
	}
}
