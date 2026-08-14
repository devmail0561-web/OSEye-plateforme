package localrules

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

const (
	ruleFileName     = "local_rules.json"
	rulePrevFileName = "local_rules_prev.json"
	maxStoredVersions = 2
)

// Store manages the local persistence and signature verification of rule sets.
// It keeps the current and previous version for rollback support.
type Store struct {
	mu        sync.RWMutex
	dir       string
	verifyKey ed25519.PublicKey

	current  *RuleSet
	previous *RuleSet
	version  atomic.Int64
}

// NewStore opens or creates the rule store at the given directory.
// verifyKey is the server's Ed25519 public key used to verify rule signatures.
func NewStore(dir string, verifyKey ed25519.PublicKey) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("localrules: mkdir store: %w", err)
	}

	s := &Store{
		dir:       dir,
		verifyKey: verifyKey,
	}

	// Load existing rules from disk if available.
	if current, err := s.loadFromFile(ruleFileName); err == nil {
		s.current = current
		s.version.Store(current.Version)
	}
	if prev, err := s.loadFromFile(rulePrevFileName); err == nil {
		s.previous = prev
	}

	return s, nil
}

// Update atomically replaces the current rule set with a new one after verifying the signature.
// The previous version is kept for rollback.
func (s *Store) Update(data []byte) error {
	rs, err := ParseRuleSet(data)
	if err != nil {
		return err
	}

	if err := s.verifySignature(rs); err != nil {
		return fmt.Errorf("localrules: signature verification failed: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject rule sets with lower or equal version (monotonic).
	if s.current != nil && rs.Version <= s.current.Version {
		return fmt.Errorf("localrules: version %d <= current %d (monotonic violation)", rs.Version, s.current.Version)
	}

	// Shift current → previous.
	if s.current != nil {
		s.previous = s.current
		if err := s.saveToFile(rulePrevFileName, s.previous); err != nil {
			slog.Warn("localrules: failed to save previous rules", "err", err)
		}
	}

	s.current = rs
	s.version.Store(rs.Version)

	if err := s.saveToFile(ruleFileName, rs); err != nil {
		slog.Warn("localrules: failed to persist current rules", "err", err)
	}

	slog.Info("localrules: rules updated", "version", rs.Version, "count", len(rs.Rules))
	return nil
}

// Rollback reverts to the previous rule set version.
func (s *Store) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.previous == nil {
		return fmt.Errorf("localrules: no previous version available for rollback")
	}

	s.current = s.previous
	s.previous = nil
	s.version.Store(s.current.Version)

	if err := s.saveToFile(ruleFileName, s.current); err != nil {
		slog.Warn("localrules: failed to persist rollback rules", "err", err)
	}

	slog.Warn("localrules: rolled back to version", "version", s.current.Version)
	return nil
}

// Current returns the active rule set (nil if none loaded).
func (s *Store) Current() *RuleSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Version returns the current rule set version.
func (s *Store) Version() int64 {
	return s.version.Load()
}

func (s *Store) verifySignature(rs *RuleSet) error {
	if s.verifyKey == nil {
		// No verification key configured — skip signature check.
		// This matches the existing behavior where require_agent_keys defaults to false.
		return nil
	}

	if len(rs.Signature) == 0 {
		return fmt.Errorf("rule set has no signature")
	}

	// The signed message is the JSON encoding of rules + version without the signature field.
	msg := struct {
		Version int64  `json:"version"`
		Rules   []Rule `json:"rules"`
	}{
		Version: rs.Version,
		Rules:   rs.Rules,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal for verification: %w", err)
	}

	if !ed25519.Verify(s.verifyKey, msgBytes, rs.Signature) {
		return fmt.Errorf("ed25519 signature invalid")
	}
	return nil
}

func (s *Store) loadFromFile(filename string) (*RuleSet, error) {
	path := filepath.Join(s.dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := ParseRuleSet(data)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

func (s *Store) saveToFile(filename string, rs *RuleSet) error {
	data, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, filename)
	return os.WriteFile(path, data, 0o600)
}

// ForceSet directly sets the current rule set (for testing only).
func (s *Store) ForceSet(rs *RuleSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = rs
	if rs != nil {
		s.version.Store(rs.Version)
	}
}

// ForceSetPrev directly sets the previous rule set (for testing only).
func (s *Store) ForceSetPrev(rs *RuleSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previous = rs
}
