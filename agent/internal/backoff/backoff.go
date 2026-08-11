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
	next := current * 2
	if next > max {
		next = max
	}
	if next <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(next) + 1))
}
