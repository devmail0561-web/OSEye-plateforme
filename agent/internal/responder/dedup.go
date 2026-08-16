//go:build linux

package responder

import (
	"sort"
	"sync"
	"time"
)

// maxEntries is the hard cap on the number of dedup entries kept in memory.
// When the map reaches this size, expired entries are purged first; if the map
// still holds more than maxEntries/2 live entries, the oldest half is evicted.
// This bounds memory to O(maxEntries) regardless of TTL length.
const maxEntries = 1000

// Deduplicator prevents repeated execution of the same action on the same
// target within a TTL window. Key = "{command_type}|{target}".
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

	// G-D-02: enforce a strict memory bound before inserting.
	// Phase 1 — remove all expired entries.
	// Phase 2 — if still at or above half capacity, evict the oldest entries
	//            (those with the earliest expiry) down to maxEntries/2.
	// This guarantees len(d.seen) < maxEntries at all times, even when TTLs
	// are long and no entries have expired yet.
	if len(d.seen) >= maxEntries {
		d.cleanup(now)
		if len(d.seen) >= maxEntries/2 {
			d.evictOldest(maxEntries / 2)
		}
	}

	d.seen[key] = now.Add(d.ttl)
	return true
}

// cleanup removes expired entries. Called under lock.
func (d *Deduplicator) cleanup(now time.Time) {
	for k, exp := range d.seen {
		if now.After(exp) {
			delete(d.seen, k)
		}
	}
}

// evictOldest removes entries with the earliest expiry times until
// len(d.seen) <= target. Called under lock.
// Complexity: O(n log n) where n = len(d.seen).
func (d *Deduplicator) evictOldest(target int) {
	type kv struct {
		key string
		exp time.Time
	}
	entries := make([]kv, 0, len(d.seen))
	for k, exp := range d.seen {
		entries = append(entries, kv{k, exp})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].exp.Before(entries[j].exp)
	})
	toDelete := len(entries) - target
	for i := 0; i < toDelete; i++ {
		delete(d.seen, entries[i].key)
	}
}
