// Package enrollment handles automatic agent enrollment on first boot.
//
// If OSEYE_ENROLL_TOKEN is set and TLSCertFile does not exist yet, the agent:
//  1. GET  {EnrollServerURL}/api/v1/enroll/{token} → downloads the CA cert
//  2. Generates an RSA 2048 key pair + PKCS#10 CSR (CN = hostname)
//  3. POST {EnrollServerURL}/api/v1/enroll/{token} → receives the signed cert
//  4. Writes CACertFile, TLSKeyFile, TLSCertFile to disk
//
// On subsequent boots, TLSCertFile exists so Enroll is a no-op.
package enrollment

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// EnrollParams holds the fields required to perform enrollment.
type EnrollParams struct {
	TLSCertFile   string
	TLSKeyFile    string
	CACertFile    string
	EnrollURL     string
	EnrollToken   string
	Hostname      string
}

// NeedsEnrollment returns true if enrollment should be attempted.
func NeedsEnrollment(p EnrollParams) bool {
	if p.EnrollToken == "" || p.EnrollURL == "" {
		return false
	}
	_, err := os.Stat(p.TLSCertFile)
	return os.IsNotExist(err)
}

// Enroll performs the full enrollment flow. Returns nil if not needed.
// CIA — Confidentialité : all HTTP calls should go over HTTPS in production.
func Enroll(p EnrollParams) error {
	if !NeedsEnrollment(p) {
		if p.EnrollToken != "" {
			slog.Info("enrollment: cert already present, skipping", "path", p.TLSCertFile)
		}
		return nil
	}

	slog.Info("enrollment: starting", "server", p.EnrollURL, "hostname", p.Hostname)

	// Step 1: fetch CA cert
	caPEM, err := fetchCACert(p.EnrollURL, p.EnrollToken)
	if err != nil {
		return fmt.Errorf("enrollment: fetch CA cert: %w", err)
	}

	// Step 2: generate RSA 2048 key + CSR
	privKey, csrPEM, err := generateCSR(p.Hostname)
	if err != nil {
		return fmt.Errorf("enrollment: generate CSR: %w", err)
	}

	// Step 3: POST CSR → get signed cert
	certPEM, err := signCSR(p.EnrollURL, p.EnrollToken, csrPEM, p.Hostname)
	if err != nil {
		return fmt.Errorf("enrollment: sign CSR: %w", err)
	}

	// Step 4: write files atomically
	if err := writeFile(p.CACertFile, caPEM, 0o644); err != nil {
		return fmt.Errorf("enrollment: write CA cert: %w", err)
	}
	privKeyPEM, err := marshalPrivKey(privKey)
	if err != nil {
		return fmt.Errorf("enrollment: marshal private key: %w", err)
	}
	// CIA — Confidentialité : private key readable only by owner.
	if err := writeFile(p.TLSKeyFile, privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("enrollment: write TLS key: %w", err)
	}
	if err := writeFile(p.TLSCertFile, certPEM, 0o644); err != nil {
		return fmt.Errorf("enrollment: write TLS cert: %w", err)
	}

	slog.Info("enrollment: complete",
		"cert", p.TLSCertFile,
		"key",  p.TLSKeyFile,
		"ca",   p.CACertFile,
	)
	return nil
}

// ------------------------------------------------------------------
// HTTP helpers
// ------------------------------------------------------------------

var httpClient = &http.Client{Timeout: 30 * time.Second}

func fetchCACert(serverURL, token string) ([]byte, error) {
	url := serverURL + "/api/v1/enroll/" + token
	resp, err := httpClient.Get(url) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func signCSR(serverURL, token, csrPEM, hostname string) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"csr":      csrPEM,
		"hostname": hostname,
	})
	if err != nil {
		return nil, err
	}

	url := serverURL + "/api/v1/enroll/" + token
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, raw)
	}

	var result struct {
		Cert string `json:"cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return []byte(result.Cert), nil
}

// ------------------------------------------------------------------
// Crypto helpers
// ------------------------------------------------------------------

func generateCSR(hostname string) (*rsa.PrivateKey, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, "", err
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}))
	return privKey, csrPEM, nil
}

func marshalPrivKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ------------------------------------------------------------------
// File helpers
// ------------------------------------------------------------------

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Write to tmp then rename for atomicity
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
