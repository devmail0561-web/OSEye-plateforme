//go:build linux

package responder_test

import (
	"testing"
	"time"

	"github.com/oseye/agent/internal/responder"
)

func TestDeduplicatorAllowsFirst(t *testing.T) {
	d := responder.NewDeduplicator(60 * time.Second)
	if !d.Allow("BLOCK_IP", "1.2.3.4") {
		t.Fatal("first call should be allowed")
	}
}

func TestDeduplicatorBlocksDuplicate(t *testing.T) {
	d := responder.NewDeduplicator(60 * time.Second)
	d.Allow("BLOCK_IP", "1.2.3.4")
	if d.Allow("BLOCK_IP", "1.2.3.4") {
		t.Fatal("duplicate within TTL should be blocked")
	}
}

func TestDeduplicatorDifferentTargetsAllowed(t *testing.T) {
	d := responder.NewDeduplicator(60 * time.Second)
	d.Allow("BLOCK_IP", "1.2.3.4")
	if !d.Allow("BLOCK_IP", "5.6.7.8") {
		t.Fatal("different target should be allowed")
	}
}

func TestDeduplicatorDifferentTypesAllowed(t *testing.T) {
	d := responder.NewDeduplicator(60 * time.Second)
	d.Allow("BLOCK_IP", "1.2.3.4")
	if !d.Allow("QUARANTINE_FILE", "1.2.3.4") {
		t.Fatal("different command type should be allowed")
	}
}

func TestDeduplicatorAllowsAfterTTL(t *testing.T) {
	d := responder.NewDeduplicator(10 * time.Millisecond)
	d.Allow("BLOCK_IP", "1.2.3.4")
	time.Sleep(20 * time.Millisecond)
	if !d.Allow("BLOCK_IP", "1.2.3.4") {
		t.Fatal("should be allowed after TTL expires")
	}
}
