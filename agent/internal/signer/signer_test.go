package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEphemeral(t *testing.T) {
	s, err := NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral() error = %v", err)
	}
	if s == nil {
		t.Fatal("NewEphemeral() returned nil signer")
	}
}

func TestPublicKeyLen(t *testing.T) {
	s, _ := NewEphemeral()
	pub := s.PublicKey()
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("PublicKey() len = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestSignLen(t *testing.T) {
	s, _ := NewEphemeral()
	sig, err := s.Sign([]byte("test payload"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("Sign() len = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

func TestSignVerify(t *testing.T) {
	s, _ := NewEphemeral()
	data := []byte("batch of events to sign")

	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	pub := ed25519.PublicKey(s.PublicKey())
	if !ed25519.Verify(pub, data, sig) {
		t.Error("ed25519.Verify failed for freshly signed data")
	}
}

func TestSignWrongDataFails(t *testing.T) {
	s, _ := NewEphemeral()
	sig, _ := s.Sign([]byte("original data"))

	pub := ed25519.PublicKey(s.PublicKey())
	if ed25519.Verify(pub, []byte("tampered data"), sig) {
		t.Error("ed25519.Verify should fail for tampered data")
	}
}

func TestNewFromPEMFile(t *testing.T) {
	// Generate a key and write it as PKCS8 PEM
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ed25519.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write PEM file: %v", err)
	}

	s, err := New(keyPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	data := []byte("hello from file-backed signer")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.PublicKey()), data, sig) {
		t.Error("verify failed for file-backed signer")
	}
}

func TestNewMissingFile(t *testing.T) {
	_, err := New("/tmp/this-file-does-not-exist-oseye.pem")
	if err == nil {
		t.Error("New() with missing file should return error")
	}
}

func TestNewInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a pem"), 0600)
	_, err := New(bad)
	if err == nil {
		t.Error("New() with invalid PEM should return error")
	}
}
