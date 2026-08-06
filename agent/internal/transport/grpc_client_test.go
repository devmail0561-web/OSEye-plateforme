package transport

import (
	"crypto/ed25519"
	"testing"

	"github.com/zeebo/blake3"
	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/chain"
	"github.com/oseye/agent/internal/config"
	"github.com/oseye/agent/internal/signer"
)

// TestBatchSignatureEmptyBatch verifies that batchSignature does not panic on
// an empty event list and returns a 64-byte Ed25519 signature.
func TestBatchSignatureEmptyBatch(t *testing.T) {
	t.Parallel()

	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}

	sig, err := batchSignature(ch, s, nil)
	if err != nil {
		t.Fatalf("batchSignature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}
}

// TestBatchSignatureCorrectness verifies that batchSignature produces the
// expected BLAKE3(hash_chain[0]||…||hash_chain[N-1]) digest and a valid
// Ed25519 signature over it.
func TestBatchSignatureCorrectness(t *testing.T) {
	t.Parallel()

	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}

	events := []*gen.UniversalEventPB{
		{HashChain: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")},
		{HashChain: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
		{HashChain: []byte("cccccccccccccccccccccccccccccccc")},
	}

	// Compute the expected digest manually.
	h := blake3.New()
	for _, ev := range events {
		h.Write(ev.GetHashChain())
	}
	var expected [32]byte
	h.Sum(expected[:0])

	sig, err := batchSignature(ch, s, events)
	if err != nil {
		t.Fatalf("batchSignature: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", ed25519.SignatureSize, len(sig))
	}

	// Verify the signature against the expected digest using the public key.
	pubKey := ed25519.PublicKey(s.PublicKey())
	if !ed25519.Verify(pubKey, expected[:], sig) {
		t.Fatal("signature verification failed: batch signature does not match expected digest")
	}
}

// TestBatchSignatureDifferentEvents verifies that two different event sets
// produce different signatures (collision resistance).
func TestBatchSignatureDifferentEvents(t *testing.T) {
	t.Parallel()

	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}

	eventsA := []*gen.UniversalEventPB{
		{HashChain: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")},
	}
	eventsB := []*gen.UniversalEventPB{
		{HashChain: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
	}

	sigA, err := batchSignature(ch, s, eventsA)
	if err != nil {
		t.Fatalf("batchSignature A: %v", err)
	}
	sigB, err := batchSignature(ch, s, eventsB)
	if err != nil {
		t.Fatalf("batchSignature B: %v", err)
	}

	if string(sigA) == string(sigB) {
		t.Fatal("expected different signatures for different event sets")
	}
}

// TestNewClientMissingCerts verifies that New returns a descriptive error when
// certificate files do not exist (no network connection is made).
func TestNewClientMissingCerts(t *testing.T) {
	t.Parallel()

	ch := chain.New()
	s, err := signer.NewEphemeral()
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}

	cfg := &config.Config{
		GRPCAddr:    "localhost:9999",
		TLSCertFile: "/nonexistent/cert.pem",
		TLSKeyFile:  "/nonexistent/key.pem",
		CACertFile:  "/nonexistent/ca.pem",
	}

	_, err = New(cfg, ch, s)
	if err == nil {
		t.Fatal("expected error when certificate files do not exist, got nil")
	}
}
