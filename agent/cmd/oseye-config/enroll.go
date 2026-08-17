package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const enrollUsage = `oseye-config enroll — enroll this host as an OSEye agent

Usage:
  oseye-config enroll --server HOST:PORT --token TOKEN [options]

Required:
  --server   HOST:PORT   Server API address (e.g. oseye.example.com:8000)
  --token    TOKEN       One-time enrollment token (from 'oseye-server init' or 'oseye-server setup')

Options:
  --grpc-port  N         Server gRPC port for the agent connection (default: 50051)
  --agent-id   UUID      Override the auto-generated agent UUID
  --certs-dir  PATH      Directory for certificates (default: /etc/oseye/certs)
  --env-file   PATH      Agent env file to write (default: /etc/oseye/agent.env)
  --help                 Show this help
`

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, enrollUsage) }

	server   := fs.String("server", "", "SERVER:PORT (required)")
	token    := fs.String("token", "", "enrollment token (required)")
	grpcPort := fs.String("grpc-port", "50051", "server gRPC port")
	agentID  := fs.String("agent-id", "", "agent UUID (auto-generated if empty)")
	certsDir := fs.String("certs-dir", "/etc/oseye/certs", "certificate directory")
	envFile  := fs.String("env-file", "/etc/oseye/agent.env", "agent env file path")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "error: --server and --token are required")
		fmt.Fprint(os.Stderr, enrollUsage)
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		fatal("oseye-config enroll must be run as root")
	}

	// Strip any user-supplied scheme, then parse host:port (handles IPv6)
	rawServer := strings.TrimPrefix(strings.TrimPrefix(*server, "https://"), "http://")
	apiBase := "https://" + rawServer

	serverHost, _, err := net.SplitHostPort(rawServer)
	if err != nil {
		// No port in the string — treat the whole value as the host
		serverHost = rawServer
	}

	// Resolve hostname
	hostname, err := os.Hostname()
	if err != nil {
		fatal("resolve hostname: " + err.Error())
	}

	// Auto-generate agent ID
	if *agentID == "" {
		data, err := os.ReadFile("/proc/sys/kernel/random/uuid")
		if err == nil {
			*agentID = strings.TrimSpace(string(data))
		} else {
			*agentID = mustGenUUID()
		}
	}

	fmt.Println("==> OSEye Agent Enrollment")
	fmt.Printf("    Server   : %s\n", *server)
	fmt.Printf("    Hostname : %s\n", hostname)
	fmt.Printf("    Agent ID : %s\n\n", *agentID)

	// ── Create directories ──────────────────────────────────────────────────
	if err := os.MkdirAll(*certsDir, 0700); err != nil {
		fatal("create certs dir: " + err.Error())
	}
	if err := os.MkdirAll(filepath.Dir(*envFile), 0700); err != nil {
		fatal("create env dir: " + err.Error())
	}

	// ── Step 1: Fetch CA certificate (TOFU) ────────────────────────────────
	fmt.Println("==> Fetching CA certificate (TOFU)...")
	caCertPath := filepath.Join(*certsDir, "ca.crt")
	fetchCA(apiBase, *token, caCertPath)
	fmt.Printf("    Saved to %s\n", caCertPath)

	// ── Step 2: Generate RSA-2048 key pair ─────────────────────────────────
	fmt.Println("==> Generating agent key pair (RSA-2048)...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal("generate key: " + err.Error())
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fatal("marshal private key: " + err.Error())
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	agentKeyPath := filepath.Join(*certsDir, "agent.key")
	if err := writeSecureFile(agentKeyPath, keyPEM, 0600); err != nil {
		fatal("write agent key: " + err.Error())
	}

	// ── Step 3: Create CSR ─────────────────────────────────────────────────
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"OSEye"},
			Country:      []string{"FR"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		fatal("create CSR: " + err.Error())
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// ── Step 4: POST CSR for signing ───────────────────────────────────────
	fmt.Println("==> Submitting CSR for signing...")
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		fatal("read CA cert: " + err.Error())
	}

	agentCertPEM := signCSR(apiBase, *token, caCertPEM, csrPEM, hostname)

	agentCertPath := filepath.Join(*certsDir, "agent.crt")
	if err := writeSecureFile(agentCertPath, []byte(agentCertPEM), 0644); err != nil {
		fatal("write agent cert: " + err.Error())
	}
	fmt.Printf("    Saved to %s\n", agentCertPath)

	// ── Step 5: Fix ownership (certs should belong to oseye user) ──────────
	fmt.Println("==> Fixing certificate ownership...")
	if err := chownToOseye(*certsDir); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to chown certs to oseye: %v\n", err)
		fmt.Fprintln(os.Stderr, "         Run manually: sudo chown -R oseye:oseye /etc/oseye/certs/")
	}

	// ── Step 6: Write agent.env ────────────────────────────────────────────
	fmt.Printf("==> Writing %s...\n", *envFile)
	envContent := fmt.Sprintf(
		"# Generated by oseye-config enroll on %s\n"+
			"OSEYE_GRPC_ADDR=%s:%s\n"+
			"OSEYE_TLS_CERT=%s\n"+
			"OSEYE_TLS_KEY=%s\n"+
			"OSEYE_TLS_CA=%s\n"+
			"OSEYE_AGENT_ID=%s\n"+
			"OSEYE_BUFFER_PATH=/var/lib/oseye/buffer.db\n"+
			"OSEYE_MAX_CPU_PCT=4.0\n"+
			"OSEYE_MAX_MEM_MB=256\n"+
			"OSEYE_BATCH_SIZE=1000\n"+
			"OSEYE_BATCH_TIMEOUT_MS=1000\n"+
			"OSEYE_FANOTIFY_PATHS=/etc/passwd,/etc/shadow,/root/.ssh\n"+
			`OSEYE_INOTIFY_WATCHES=[{"path":"/tmp","recursive":false,"mask":4095}]`+"\n",
		time.Now().UTC().Format(time.RFC3339),
		serverHost, *grpcPort,
		agentCertPath, agentKeyPath, caCertPath,
		*agentID,
	)

	if err := writeSecureFile(*envFile, []byte(envContent), 0600); err != nil {
		fatal("write env file: " + err.Error())
	}

	// ── Step 7: Fix env file ownership ─────────────────────────────────────
	if err := chownFileToOseye(*envFile); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to chown agent.env to oseye: %v\n", err)
	}

	// ── Step 8: Enable systemd service ────────────────────────────────────
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: systemctl daemon-reload: %v\n%s\n", err, out)
		}
		if out, err := exec.Command("systemctl", "enable", "--now", "oseye-agent").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: systemctl enable oseye-agent: %v\n%s\n", err, out)
			fmt.Fprintln(os.Stderr, "         Start manually: systemctl start oseye-agent")
		} else {
			fmt.Println("\n==> oseye-agent enabled and started.")
		}
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║           Agent Enrollment Complete                       ║")
	fmt.Println("╠══════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Certs    : %s/\n", *certsDir)
	fmt.Printf("║ Env file : %s\n", *envFile)
	fmt.Printf("║ Agent ID : %s\n", *agentID)
	fmt.Printf("║ Server   : %s:%s (gRPC)\n", serverHost, *grpcPort)
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
}

// fetchCA downloads the CA certificate using TOFU (InsecureSkipVerify for
// this single bootstrap request only). The token is transmitted over an
// unverified TLS channel — this is unavoidable for TOFU but the CA fingerprint
// should be verified out-of-band after enrollment.
func fetchCA(apiBase, token, destPath string) {
	slog.Warn("fetchCA: InsecureSkipVerify=true for TOFU bootstrap — verify CA fingerprint after enrollment")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — intentional TOFU
		},
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, apiBase+"/api/v1/enroll/ca", nil)
	if err != nil {
		fatal("build CA request: " + err.Error())
	}
	req.Header.Set("X-Enrollment-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		fatal("fetch CA cert: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		fatal(fmt.Sprintf("fetch CA cert: HTTP %d — %s", resp.StatusCode, body))
	}

	// G-E-03: cap response size to 1 MB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fatal("read CA cert body: " + err.Error())
	}
	if err := writeSecureFile(destPath, body, 0644); err != nil {
		fatal("write CA cert: " + err.Error())
	}
}

// signCSR posts the CSR to the server and returns the signed agent certificate PEM.
func signCSR(apiBase, token string, caCertPEM []byte, csrPEM, hostname string) string {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		fatal("CA certificate PEM is invalid or empty — cannot build TLS pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 30 * time.Second,
	}

	payload, err := json.Marshal(map[string]string{
		"csr":      csrPEM,
		"hostname": hostname,
	})
	if err != nil {
		fatal("marshal CSR payload: " + err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/v1/enroll/sign",
		strings.NewReader(string(payload)))
	if err != nil {
		fatal("build sign request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		fatal("sign CSR: " + err.Error())
	}
	defer resp.Body.Close()

	// G-E-03: cap response size to 1 MB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fatal("read sign response: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Sprintf("sign CSR: HTTP %d — %s", resp.StatusCode, body))
	}

	var result struct {
		Cert string `json:"cert"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Cert == "" {
		fatal(fmt.Sprintf("unexpected sign response: %s", body))
	}

	// G-E-04: validate the returned certificate — CN == hostname and signature from CA.
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		fatal("CA cert PEM is invalid — cannot validate returned cert")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		fatal("parse CA cert for validation: " + err.Error())
	}
	certBlock, _ := pem.Decode([]byte(result.Cert))
	if certBlock == nil {
		fatal("returned cert PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fatal("parse returned cert: " + err.Error())
	}
	if cert.Subject.CommonName != hostname {
		fatal(fmt.Sprintf("cert CN %q does not match hostname %q", cert.Subject.CommonName, hostname))
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		fatal("cert signature validation failed: " + err.Error())
	}

	return result.Cert
}

// writeSecureFile creates a file with the given mode from the first open call — no TOCTOU.
func writeSecureFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// mustGenUUID generates a random UUID v4 using crypto/rand as fallback.
func mustGenUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		fatal("generate UUID: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// chownToOseye recursively changes ownership of a directory to oseye:oseye.
func chownToOseye(dir string) error {
	u, err := user.Lookup("oseye")
	if err != nil {
		return fmt.Errorf("lookup user oseye: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

// chownFileToOseye changes ownership of a single file to oseye:oseye.
func chownFileToOseye(file string) error {
	u, err := user.Lookup("oseye")
	if err != nil {
		return fmt.Errorf("lookup user oseye: %w", err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return os.Chown(file, uid, gid)
}
