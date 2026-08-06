package signer

import (
	"crypto/rand"
	"testing"
)

var sigSink []byte

// BenchmarkSign_1KB measures Ed25519 signing on a 1 KB batch digest.
// Target: production calls at 2 batches/s → need >2 ops/s with comfortable margin.
func BenchmarkSign_1KB(b *testing.B) {
	s, err := NewEphemeral()
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sigSink, err = s.Sign(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSign_32B measures Ed25519 signing on a 32-byte hash (real use case:
// BLAKE3(hash_chain[0] || ... || hash_chain[N-1]) = 32 bytes).
func BenchmarkSign_32B(b *testing.B) {
	s, err := NewEphemeral()
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sigSink, err = s.Sign(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBatchSign_1000 measures the time to sign 1000 batch digests sequentially.
// Production frequency: every 500ms. Pass if total < 50ms.
func BenchmarkBatchSign_1000(b *testing.B) {
	s, err := NewEphemeral()
	if err != nil {
		b.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1000; j++ {
			sigSink, err = s.Sign(digest)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
