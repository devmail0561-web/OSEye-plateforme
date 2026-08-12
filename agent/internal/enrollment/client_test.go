package enrollment_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	t.Setenv("OSEYE_INSECURE", "true")
	tmp := t.TempDir()

	// Generate a real in-memory CA so the server can sign the CSR and
	// production-code validation (G-E-04: CN match + CA signature) passes.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Fake enrollment server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Step 1 — return real CA cert PEM
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(caPEM)

		case http.MethodPost:
			// Step 3 — parse CSR from request, sign with CA, return cert
			var body struct {
				CSR      string `json:"csr"`
				Hostname string `json:"hostname"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			csrBlock, _ := pem.Decode([]byte(body.CSR))
			if csrBlock == nil {
				http.Error(w, "bad CSR", http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
			if err != nil {
				http.Error(w, "parse CSR: "+err.Error(), http.StatusBadRequest)
				return
			}

			certTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      csr.Subject,
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
				return
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"cert": string(certPEM),
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
