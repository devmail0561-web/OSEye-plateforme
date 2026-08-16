package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/oseye/agent/internal/config"
)

var version = "dev"

const envFile = "/etc/oseye/agent.env"

var sensitiveKeys = map[string]bool{
	"OSEYE_ENROLL_TOKEN":       true,
	"OSEYE_ED25519_SIGNING_KEY": true,
}

var usage = `oseye-config — Agent configuration management

Usage:
  oseye-config enroll                Enroll this host as an OSEye agent (see --help)
  oseye-config show                  Show current effective configuration
  oseye-config validate              Validate current configuration
  oseye-config get <KEY>             Get a specific config value
  oseye-config set <KEY>=<VALUE>     Set a value in the env file
  oseye-config unset <KEY>           Remove a key from the env file
  oseye-config env-file              Show the env file path in use
  oseye-config check-files           Verify that referenced files (certs, keys) exist
  oseye-config help                  Show this help

Environment:
  OSEYE_ENV_FILE    Override the env file path (default: /etc/oseye/agent.env)

Keys (environment variable names):
  OSEYE_GRPC_ADDR, OSEYE_TLS_CERT, OSEYE_TLS_KEY, OSEYE_TLS_CA,
  OSEYE_ED25519_SIGNING_KEY, OSEYE_BUFFER_PATH, OSEYE_AGENT_ID,
  OSEYE_BATCH_SIZE, OSEYE_BATCH_TIMEOUT_MS, OSEYE_MAX_CPU_PCT,
  OSEYE_MAX_MEM_MB, OSEYE_FANOTIFY_PATHS, OSEYE_INOTIFY_WATCHES,
  OSEYE_JOURNALD_PRIORITY, OSEYE_JOURNALD_UNITS, OSEYE_SYSLOG_ADDR,
  OSEYE_QUARANTINE_DIR, OSEYE_ENROLL_URL, OSEYE_ENROLL_TOKEN
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	target := resolveEnvFile()

	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "show":
		cmdShow()
	case "validate":
		cmdValidate()
	case "get":
		if len(os.Args) < 3 {
			fatal("usage: oseye-config get <KEY>")
		}
		cmdGet(os.Args[2])
	case "set":
		if len(os.Args) < 3 {
			fatal("usage: oseye-config set <KEY>=<VALUE>")
		}
		cmdSet(target, os.Args[2])
	case "unset":
		if len(os.Args) < 3 {
			fatal("usage: oseye-config unset <KEY>")
		}
		cmdUnset(target, os.Args[2])
	case "env-file":
		fmt.Println(target)
	case "check-files":
		cmdCheckFiles()
	case "version", "--version", "-v":
		fmt.Printf("oseye-config %s\n", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func cmdShow() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load error: %v\n", err)
		fmt.Println("\nRaw environment values (sensitive keys masked):")
		showRawEnv()
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tVALUE")
	fmt.Fprintln(w, "---\t-----")
	fmt.Fprintf(w, "OSEYE_GRPC_ADDR\t%s\n", cfg.GRPCAddr)
	fmt.Fprintf(w, "OSEYE_TLS_CERT\t%s\n", cfg.TLSCertFile)
	fmt.Fprintf(w, "OSEYE_TLS_KEY\t%s\n", cfg.TLSKeyFile)
	fmt.Fprintf(w, "OSEYE_TLS_CA\t%s\n", cfg.CACertFile)
	fmt.Fprintf(w, "OSEYE_ED25519_SIGNING_KEY\t%s\n", cfg.Ed25519KeyFile)
	fmt.Fprintf(w, "OSEYE_BUFFER_PATH\t%s\n", cfg.BufferPath)
	fmt.Fprintf(w, "OSEYE_AGENT_ID\t%s\n", cfg.AgentID)
	fmt.Fprintf(w, "OSEYE_BATCH_SIZE\t%d\n", cfg.BatchSize)
	fmt.Fprintf(w, "OSEYE_BATCH_TIMEOUT_MS\t%d\n", cfg.BatchTimeout.Milliseconds())
	fmt.Fprintf(w, "OSEYE_MAX_CPU_PCT\t%.1f\n", cfg.MaxCPUPct)
	fmt.Fprintf(w, "OSEYE_MAX_MEM_MB\t%d\n", cfg.MaxMemMB)
	fmt.Fprintf(w, "OSEYE_FANOTIFY_PATHS\t%s\n", strings.Join(cfg.FanotifyPaths, ","))
	watches, _ := json.Marshal(cfg.InotifyWatches)
	fmt.Fprintf(w, "OSEYE_INOTIFY_WATCHES\t%s\n", string(watches))
	fmt.Fprintf(w, "OSEYE_JOURNALD_PRIORITY\t%s\n", cfg.JournaldPriority)
	fmt.Fprintf(w, "OSEYE_JOURNALD_UNITS\t%s\n", strings.Join(cfg.JournaldUnits, ","))
	fmt.Fprintf(w, "OSEYE_SYSLOG_ADDR\t%s\n", cfg.SyslogAddr)
	fmt.Fprintf(w, "OSEYE_QUARANTINE_DIR\t%s\n", cfg.QuarantineDir)
	fmt.Fprintf(w, "OSEYE_ENROLL_URL\t%s\n", cfg.EnrollServerURL)
	fmt.Fprintf(w, "OSEYE_ENROLL_TOKEN\t%s\n", maskSecret(cfg.EnrollToken))
	w.Flush()
}

func cmdValidate() {
	_, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK — configuration is valid")
}

func cmdGet(key string) {
	key = strings.ToUpper(key)
	if sensitiveKeys[key] {
		fmt.Fprintf(os.Stderr, "refused: %s is a sensitive key — use 'show' for masked output\n", key)
		os.Exit(1)
	}
	val := os.Getenv(key)
	if val == "" {
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s is not set and config failed to load: %v\n", key, err)
			os.Exit(1)
		}
		val = getFieldByEnvKey(cfg, key)
	}
	fmt.Println(val)
}

func cmdSet(envFilePath, assignment string) {
	parts := strings.SplitN(assignment, "=", 2)
	if len(parts) != 2 {
		fatal("usage: oseye-config set KEY=VALUE")
	}
	key, value := strings.ToUpper(parts[0]), parts[1]

	if !isValidKey(key) {
		fatal("unknown key: " + key)
	}

	// Reject newline injection
	if strings.ContainsAny(value, "\n\r") {
		fatal("value must not contain newline characters")
	}

	// Dry-run validation: temporarily set in env and validate
	old := os.Getenv(key)
	os.Setenv(key, value)
	_, err := config.Load()
	if old != "" {
		os.Setenv(key, old)
	} else {
		os.Unsetenv(key)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "validation failed with new value: %v\n", err)
		os.Exit(1)
	}

	if err := writeEnvVar(envFilePath, key, value); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write env file: %v\n", err)
		os.Exit(1)
	}

	displayValue := value
	if sensitiveKeys[key] {
		displayValue = maskSecret(value)
	}
	fmt.Printf("set %s=%s in %s\n", key, displayValue, envFilePath)
}

func cmdUnset(envFilePath, key string) {
	key = strings.ToUpper(key)
	if err := removeEnvVar(envFilePath, key); err != nil {
		fmt.Fprintf(os.Stderr, "failed to update env file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("removed %s from %s\n", key, envFilePath)
}

func cmdCheckFiles() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load error: %v\n", err)
		os.Exit(1)
	}

	paths := map[string]string{
		"TLS cert (OSEYE_TLS_CERT)":                cfg.TLSCertFile,
		"TLS key (OSEYE_TLS_KEY)":                  cfg.TLSKeyFile,
		"CA cert (OSEYE_TLS_CA)":                   cfg.CACertFile,
		"Ed25519 key (OSEYE_ED25519_SIGNING_KEY)":  cfg.Ed25519KeyFile,
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tPATH\tSTATUS")
	fmt.Fprintln(w, "----\t----\t------")

	hasError := false
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, label := range keys {
		p := paths[label]
		status := "OK"
		if _, err := os.Stat(p); os.IsNotExist(err) {
			status = "MISSING"
			hasError = true
		} else if err != nil {
			status = "ERROR: " + err.Error()
			hasError = true
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", label, p, status)
	}

	dirs := map[string]string{
		"Buffer dir":     filepath.Dir(cfg.BufferPath),
		"Quarantine dir": cfg.QuarantineDir,
	}
	dirKeys := make([]string, 0, len(dirs))
	for k := range dirs {
		dirKeys = append(dirKeys, k)
	}
	sort.Strings(dirKeys)
	for _, label := range dirKeys {
		p := dirs[label]
		status := "OK"
		info, err := os.Stat(p)
		if os.IsNotExist(err) {
			status = "MISSING"
			hasError = true
		} else if err != nil {
			status = "ERROR: " + err.Error()
			hasError = true
		} else if !info.IsDir() {
			status = "NOT A DIRECTORY"
			hasError = true
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", label, p, status)
	}

	w.Flush()
	if hasError {
		os.Exit(1)
	}
}

// --- file operations with locking and atomic write ---

func resolveEnvFile() string {
	if v := os.Getenv("OSEYE_ENV_FILE"); v != "" {
		return v
	}
	return envFile
}

func showRawEnv() {
	keys := allKeys()
	for _, k := range keys {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		if sensitiveKeys[k] {
			v = maskSecret(v)
		}
		fmt.Printf("  %s=%s\n", k, v)
	}
}

func writeEnvVar(path, key, value string) error {
	return withLockedEnvFile(path, func(lines []string) []string {
		found := false
		prefix := key + "="
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, prefix) {
				lines[i] = key + "=" + value
				found = true
				break
			}
		}
		if !found {
			lines = append(lines, key+"="+value)
		}
		return lines
	})
}

func removeEnvVar(path, key string) error {
	return withLockedEnvFile(path, func(lines []string) []string {
		prefix := key + "="
		var out []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, prefix) {
				out = append(out, line)
			}
		}
		return out
	})
}

// withLockedEnvFile acquires an exclusive lock, reads the file, applies the
// transform, and atomically replaces the file via temp+rename.
func withLockedEnvFile(path string, transform func([]string) []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	lockPath := path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lockFile.Close()
	defer os.Remove(lockPath)

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	lines, err := readLines(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	lines = transform(lines)

	return atomicWriteLines(path, lines)
}

func atomicWriteLines(path string, lines []string) error {
	dir := filepath.Dir(path)
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	tmp, err := os.CreateTemp(dir, ".oseye-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp to target: %w", err)
	}
	return nil
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func getFieldByEnvKey(cfg *config.Config, key string) string {
	switch key {
	case "OSEYE_GRPC_ADDR":
		return cfg.GRPCAddr
	case "OSEYE_TLS_CERT":
		return cfg.TLSCertFile
	case "OSEYE_TLS_KEY":
		return cfg.TLSKeyFile
	case "OSEYE_TLS_CA":
		return cfg.CACertFile
	case "OSEYE_ED25519_SIGNING_KEY":
		return cfg.Ed25519KeyFile
	case "OSEYE_BUFFER_PATH":
		return cfg.BufferPath
	case "OSEYE_AGENT_ID":
		return cfg.AgentID
	case "OSEYE_BATCH_SIZE":
		return strconv.Itoa(cfg.BatchSize)
	case "OSEYE_BATCH_TIMEOUT_MS":
		return strconv.FormatInt(cfg.BatchTimeout.Milliseconds(), 10)
	case "OSEYE_MAX_CPU_PCT":
		return strconv.FormatFloat(cfg.MaxCPUPct, 'f', 1, 64)
	case "OSEYE_MAX_MEM_MB":
		return strconv.Itoa(cfg.MaxMemMB)
	case "OSEYE_FANOTIFY_PATHS":
		return strings.Join(cfg.FanotifyPaths, ",")
	case "OSEYE_INOTIFY_WATCHES":
		b, _ := json.Marshal(cfg.InotifyWatches)
		return string(b)
	case "OSEYE_JOURNALD_PRIORITY":
		return cfg.JournaldPriority
	case "OSEYE_JOURNALD_UNITS":
		return strings.Join(cfg.JournaldUnits, ",")
	case "OSEYE_SYSLOG_ADDR":
		return cfg.SyslogAddr
	case "OSEYE_QUARANTINE_DIR":
		return cfg.QuarantineDir
	case "OSEYE_ENROLL_URL":
		return cfg.EnrollServerURL
	default:
		return ""
	}
}

func isValidKey(key string) bool {
	for _, k := range allKeys() {
		if k == key {
			return true
		}
	}
	return false
}

func allKeys() []string {
	return []string{
		"OSEYE_GRPC_ADDR", "OSEYE_TLS_CERT", "OSEYE_TLS_KEY", "OSEYE_TLS_CA",
		"OSEYE_ED25519_SIGNING_KEY", "OSEYE_BUFFER_PATH", "OSEYE_AGENT_ID",
		"OSEYE_BATCH_SIZE", "OSEYE_BATCH_TIMEOUT_MS", "OSEYE_MAX_CPU_PCT",
		"OSEYE_MAX_MEM_MB", "OSEYE_FANOTIFY_PATHS", "OSEYE_INOTIFY_WATCHES",
		"OSEYE_JOURNALD_PRIORITY", "OSEYE_JOURNALD_UNITS", "OSEYE_SYSLOG_ADDR",
		"OSEYE_QUARANTINE_DIR", "OSEYE_ENROLL_URL", "OSEYE_ENROLL_TOKEN",
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
