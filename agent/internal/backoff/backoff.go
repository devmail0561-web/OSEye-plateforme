// Package backoff provides a full-jitter exponential backoff helper.
// Full jitter distributes reconnection attempts uniformly across [0, next_cap],
// preventing thundering-herd spikes when many agents restart simultaneously.
package backoff

import (
	"math/rand/v2"
	"time"
)

// Next returns the next backoff delay using full jitter:
// a random duration in [0, min(current*2, max)].
func Next(current, max time.Duration) time.Duration {
	// G-B-02: a zero (or negative) current produces permanent zero backoff; seed to 1ns.
	if current <= 0 {
		current = 1
	}
	// G-B-01: guard int64 overflow when doubling — clamp to max before the multiply.
	var next time.Duration
	if current > max/2 {
		next = max
	} else {
		next = current * 2
		if next > max {
			next = max
		}
	}
	if next <= 0 {
		return 1
	}
	// Return at least 1ns so reconnect loops never stall on zero backoff.
	n := int64(next)
	if n <= 0 {
		return time.Duration(1)
	}
	jitter := time.Duration(rand.Int64N(n))
	if jitter <= 0 {
		return time.Duration(1)
	}
	return jitter
}
