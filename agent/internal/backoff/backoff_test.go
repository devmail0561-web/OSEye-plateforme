package backoff_test

import (
	"testing"
	"time"

	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/backoff"
)

func TestNextNeverExceedsMax(t *testing.T) {
	max := 30 * time.Second
	delay := 1 * time.Second
	for i := 0; i < 100; i++ {
		delay = backoff.Next(delay, max)
		if delay > max {
			t.Fatalf("iteration %d: delay %v exceeds max %v", i, delay, max)
		}
		if delay < 0 {
			t.Fatalf("iteration %d: delay %v is negative", i, delay)
		}
	}
}

func TestNextIsNonDeterministic(t *testing.T) {
	// Full jitter should produce different values across calls.
	max := 30 * time.Second
	seen := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		v := backoff.Next(1*time.Second, max)
		seen[v] = true
	}
	if len(seen) == 1 {
		t.Fatal("Next() returned the same value 50 times — jitter not applied")
	}
}

func TestNextWithZeroCurrent(t *testing.T) {
	// G-B-02: Next(0) now returns 1ns instead of 0 to prevent permanent zero backoff.
	v := backoff.Next(0, 30*time.Second)
	if v <= 0 {
		t.Fatalf("expected positive duration for zero current, got %v", v)
	}
}
