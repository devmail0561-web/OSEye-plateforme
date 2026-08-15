package chain

import (
	"sync"

	"github.com/zeebo/blake3"
)

// Chain maintains a rolling BLAKE3 hash chain over a sequence of payloads.
// Each call to Append computes: hash_chain[i] = BLAKE3(hash_chain[i-1] || payload[i]).
// The zero-value hash is 32 zero bytes, matching the protobuf default.
type Chain struct {
	mu      sync.Mutex
	current [32]byte
}

// New creates a new Chain with the initial hash set to all zeros.
func New() *Chain {
	return &Chain{}
}

// Append hashes the current chain state concatenated with payload,
// advances the chain, and returns the new 32-byte hash.
// The returned slice is valid until the next call to Append or Reset.
func (c *Chain) Append(payload []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	h := blake3.New()
	_, _ = h.Write(c.current[:])
	_, _ = h.Write(payload)
	h.Sum(c.current[:0])

	out := make([]byte, 32)
	copy(out, c.current[:])
	return out
}

// Current returns a copy of the current hash (32 bytes).
func (c *Chain) Current() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]byte, 32)
	copy(out, c.current[:])
	return out
}

// AppendTo is like Append but writes into a caller-provided buffer, avoiding
// a heap allocation. The caller can declare `var out [32]byte` on the stack.
func (c *Chain) AppendTo(payload []byte, out *[32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := blake3.New()
	_, _ = h.Write(c.current[:])
	_, _ = h.Write(payload)
	h.Sum(c.current[:0])
	*out = c.current
}

// Reset sets the chain state back to all zeros.
func (c *Chain) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.current = [32]byte{}
}
