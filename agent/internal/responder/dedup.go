//go:build linux

package responder

import (
	"sync"
	"time"
)

// Deduplicator prevents repeated execution of the same action on the same
// target within a TTL window. Key = "{command_type}:{target}".
// This avoids flooding iptables/kill when many events match the same rule.
type Deduplicator struct {
	mu  sync.Mutex
	ttl time.Duration
	// map key → expiry time
	seen map[string]time.Time
}

// NewDeduplicator creates a Deduplicator with the given TTL.
func NewDeduplicator(ttl time.Duration) *Deduplicator {
	return &Deduplicator{
		ttl:  ttl,
		seen: make(map[string]time.Time),
	}
}

// Allow returns true if this (commandType, target) pair has not been seen
// within the TTL window, and records it. Returns false if it is a duplicate.
// G-D-01: separator is "|" to avoid collision with IPv6 addresses (e.g. 2001:db8::1).
func (d *Deduplicator) Allow(commandType, target string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := commandType + "|" + target
	now := time.Now()

	if exp, ok := d.seen[key]; ok && now.Before(exp) {
		return false
	}
	d.seen[key] = now.Add(d.ttl)
	// G-D-02: only run cleanup when the map exceeds 10000 entries to bound memory.
	if len(d.seen) > 10000 {
		d.cleanup(now)
	}
	return true
}

// cleanup removes expired entries. Called under lock when the map exceeds 10000 entries.
func (d *Deduplicator) cleanup(now time.Time) {
	for k, exp := range d.seen {
		if now.After(exp) {
			delete(d.seen, k)
		}
	}
}
