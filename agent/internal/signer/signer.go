package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
)

// Signer holds an Ed25519 private key and exposes Sign/PublicKey operations.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey // cached at construction — read-only after init, no mutex needed
}

// New loads an Ed25519 private key from a PEM-encoded PKCS8 file.
func New(privateKeyPath string) (*Signer, error) {
	fi, err := os.Stat(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signer: stat key file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		// Allow override in dev/test environments only
		if os.Getenv("OSEYE_INSECURE_KEY_PERMS") != "true" {
			return nil, fmt.Errorf("signer: key file %s has permissive permissions %04o (expected 0600). Set OSEYE_INSECURE_KEY_PERMS=true to override in dev environments.", privateKeyPath, fi.Mode().Perm())
		}
		slog.Warn("signer: key file has permissive permissions (OSEYE_INSECURE_KEY_PERMS override active)",
			"path", privateKeyPath, "mode", fmt.Sprintf("%04o", fi.Mode().Perm()))
	}
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("signer: read key file: %w", err)
	}
	return parsePEM(data)
}

// NewEphemeral generates a fresh Ed25519 key pair in memory.
// Intended for tests and ephemeral agent identities.
func NewEphemeral() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate key: %w", err)
	}
	return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Sign signs data using the Ed25519 private key and returns the 64-byte signature.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	sig := ed25519.Sign(s.priv, data)
	return sig, nil
}

// PublicKey returns the 32-byte Ed25519 public key.
func (s *Signer) PublicKey() []byte {
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, s.pub)
	return out
}

// parsePEM decodes the first PEM block and parses the PKCS8 private key inside.
func parsePEM(data []byte) (*Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signer: no PEM block found")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signer: parse PKCS8 key: %w", err)
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signer: key is not Ed25519 (got %T)", key)
	}

	return &Signer{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}
