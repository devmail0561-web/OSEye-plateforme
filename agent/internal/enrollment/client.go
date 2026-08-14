// Package enrollment handles automatic agent enrollment on first boot.
//
// If OSEYE_ENROLL_TOKEN is set and TLSCertFile does not exist yet, the agent:
//  1. GET  {EnrollServerURL}/api/v1/enroll/ca              → downloads the CA cert
//         (header X-Enrollment-Token carries the token)
//  2. Generates an RSA 2048 key pair + PKCS#10 CSR (CN = hostname)
//  3. POST {EnrollServerURL}/api/v1/enroll/sign            → receives the signed cert
//         (header X-Enrollment-Token carries the token)
//  4. Validates the received cert: CN == hostname, signature from CA
//  5. Writes CACertFile, TLSKeyFile, TLSCertFile to disk
//
// On subsequent boots, TLSCertFile exists so Enroll is a no-op.
package enrollment

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"strings"
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
	// SHA-256 hex fingerprint of the expected CA cert (e.g. "aa:bb:cc..."). Empty = no pinning (TOFU).
	CACertFingerprint string
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
// CIA — Confidentialité : all HTTP calls must go over HTTPS in production.
// Set OSEYE_INSECURE=true to allow HTTP (dev/test only).
func Enroll(p EnrollParams) error {
	if !NeedsEnrollment(p) {
		if p.EnrollToken != "" {
			slog.Info("enrollment: cert already present, skipping", "path", p.TLSCertFile)
		}
		return nil
	}

	// G-E-01: enforce HTTPS to protect token and cert in transit.
	if !strings.HasPrefix(p.EnrollURL, "https://") {
		if os.Getenv("OSEYE_INSECURE") != "true" {
			return fmt.Errorf("enrollment: EnrollURL must use HTTPS (set OSEYE_INSECURE=true to allow HTTP in dev)")
		}
		slog.Warn("enrollment: EnrollURL does not use HTTPS — token and cert will be transmitted in cleartext",
			"url", p.EnrollURL)
	}

	slog.Info("enrollment: starting", "server", p.EnrollURL, "hostname", p.Hostname)

	// Step 1: fetch CA cert
	caPEM, err := fetchCACert(p.EnrollURL, p.EnrollToken)
	if err != nil {
		return fmt.Errorf("enrollment: fetch CA cert: %w", err)
	}

	if p.CACertFingerprint != "" {
		sum := sha256.Sum256(caPEM)
		got := fmt.Sprintf("%x", sum)
		// Normalize expected: remove colons and lowercase
		want := strings.ToLower(strings.ReplaceAll(p.CACertFingerprint, ":", ""))
		if got != want {
			return fmt.Errorf("enrollment: CA cert fingerprint mismatch: got %s, want %s", got, want)
		}
		slog.Info("enrollment: CA cert fingerprint verified", "fingerprint", got)
	}

	// Step 2: generate RSA 2048 key + CSR
	privKey, csrPEM, err := generateCSR(p.Hostname)
	if err != nil {
		return fmt.Errorf("enrollment: generate CSR: %w", err)
	}

	// Step 3: POST CSR → get signed cert (validated against CA)
	certPEM, err := signCSR(p.EnrollURL, p.EnrollToken, csrPEM, p.Hostname, caPEM)
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
	// G-E-02: token in header, not in URL path.
	url := serverURL + "/api/v1/enroll/ca"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Enrollment-Token", token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// G-E-03: cap response size to 1 MB.
	resp.Body = io.NopCloser(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// signCSR posts the CSR to the server and returns the signed certificate PEM.
// G-E-02: token is sent in X-Enrollment-Token header, not in the URL.
// G-E-03: response body is capped at 1 MB.
// G-E-04: returned cert is validated (CN == hostname, signature from caCert).
func signCSR(serverURL, token, csrPEM, hostname string, caPEM []byte) ([]byte, error) {
	// Parse CA cert now so we can validate the returned certificate.
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("enrollment: failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("enrollment: parse CA cert: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"csr":      csrPEM,
		"hostname": hostname,
	})
	if err != nil {
		return nil, err
	}

	// G-E-02: token in header, not in URL path.
	url := serverURL + "/api/v1/enroll/sign"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Token", token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// G-E-03: cap response size to 1 MB.
	resp.Body = io.NopCloser(io.LimitReader(resp.Body, 1<<20))
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

	certPEM := []byte(result.Cert)

	// G-E-04: validate the returned certificate.
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("enrollment: failed to decode received cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("enrollment: parse received cert: %w", err)
	}
	if cert.Subject.CommonName != hostname {
		return nil, fmt.Errorf("enrollment: cert CN %q does not match hostname %q",
			cert.Subject.CommonName, hostname)
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("enrollment: cert signature invalid: %w", err)
	}

	return certPEM, nil
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
