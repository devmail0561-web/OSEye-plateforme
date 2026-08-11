package enrollment_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/oseye/agent/internal/enrollment"
)

func TestNeedsEnrollmentNoToken(t *testing.T) {
	p := enrollment.EnrollParams{EnrollToken: "", TLSCertFile: "/nonexistent"}
	if enrollment.NeedsEnrollment(p) {
		t.Fatal("should not need enrollment when token is empty")
	}
}

func TestNeedsEnrollmentCertExists(t *testing.T) {
	tmp := t.TempDir()
	cert := filepath.Join(tmp, "agent.crt")
	_ = os.WriteFile(cert, []byte("cert"), 0o644)

	p := enrollment.EnrollParams{
		EnrollToken: "abc",
		EnrollURL:   "http://server",
		TLSCertFile: cert,
	}
	if enrollment.NeedsEnrollment(p) {
		t.Fatal("should not need enrollment when cert already exists")
	}
}

func TestEnrollSuccess(t *testing.T) {
	tmp := t.TempDir()

	// Fake server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"))
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"cert": "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n",
			})
		}
	}))
	defer srv.Close()

	p := enrollment.EnrollParams{
		TLSCertFile: filepath.Join(tmp, "agent.crt"),
		TLSKeyFile:  filepath.Join(tmp, "agent.key"),
		CACertFile:  filepath.Join(tmp, "ca.crt"),
		EnrollURL:   srv.URL,
		EnrollToken: "testtoken",
		Hostname:    "test-host",
	}

	if err := enrollment.Enroll(p); err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	for _, path := range []string{p.TLSCertFile, p.TLSKeyFile, p.CACertFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected file %s to exist: %v", path, err)
		}
	}

	// Key must be owner-readable only
	info, _ := os.Stat(p.TLSKeyFile)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions should be 0600, got %o", info.Mode().Perm())
	}
}

func TestEnrollIdempotent(t *testing.T) {
	tmp := t.TempDir()
	cert := filepath.Join(tmp, "agent.crt")
	_ = os.WriteFile(cert, []byte("existing"), 0o644)

	p := enrollment.EnrollParams{
		TLSCertFile: cert,
		TLSKeyFile:  filepath.Join(tmp, "agent.key"),
		CACertFile:  filepath.Join(tmp, "ca.crt"),
		EnrollURL:   "http://should-not-be-called",
		EnrollToken: "token",
		Hostname:    "host",
	}

	// Should return nil without calling the server
	if err := enrollment.Enroll(p); err != nil {
		t.Fatalf("Enroll should be no-op when cert exists: %v", err)
	}

	data, _ := os.ReadFile(cert)
	if string(data) != "existing" {
		t.Fatal("existing cert should not be overwritten")
	}
}
