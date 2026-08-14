package localrules

import (
	"sync"
	"time"
)

// Correlator tracks event counts and sequences within time windows for
// correlation and sequence rules. Memory is bounded by maxGroups and maxEvents.
type Correlator struct {
	mu        sync.Mutex
	counters  map[string]*counterGroup // ruleID:groupValue → counter
	sequences map[string]*sequenceTracker // ruleID:groupValue → sequence state
	maxGroups int
	maxEvents int
}

type counterGroup struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	window    time.Duration
}

type sequenceTracker struct {
	stepsMatched int
	timestamps   []time.Time
	window       time.Duration
	lastSeen     time.Time
}

// NewCorrelator creates a correlator with bounded memory.
func NewCorrelator(maxGroups, maxEvents int) *Correlator {
	return &Correlator{
		counters:  make(map[string]*counterGroup, maxGroups),
		sequences: make(map[string]*sequenceTracker, maxGroups),
		maxGroups: maxGroups,
		maxEvents: maxEvents,
	}
}

// IncrementCounter adds an event to a correlation counter and returns true if
// the count threshold has been reached within the time window.
func (c *Correlator) IncrementCounter(ruleID, groupValue string, threshold int, windowSec int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := ruleID + ":" + groupValue
	now := time.Now()
	window := time.Duration(windowSec) * time.Second

	cg, exists := c.counters[key]
	if !exists {
		c.evictCountersIfNeeded()
		cg = &counterGroup{
			count:     0,
			firstSeen: now,
			lastSeen:  now,
			window:    window,
		}
		c.counters[key] = cg
	}

	// Reset if outside window.
	if now.Sub(cg.firstSeen) > window {
		cg.count = 0
		cg.firstSeen = now
	}

	cg.count++
	cg.lastSeen = now

	return cg.count >= threshold
}

// AdvanceSequence checks whether an event matches the next expected step in a
// sequence rule. Returns true if the full sequence has been matched.
func (c *Correlator) AdvanceSequence(ruleID, groupValue string, stepIndex int, totalSteps int, windowSec int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := ruleID + ":" + groupValue
	now := time.Now()
	window := time.Duration(windowSec) * time.Second

	st, exists := c.sequences[key]
	if !exists {
		if stepIndex != 0 {
			return false
		}
		c.evictSequencesIfNeeded()
		st = &sequenceTracker{
			stepsMatched: 0,
			timestamps:   make([]time.Time, 0, totalSteps),
			window:       window,
		}
		c.sequences[key] = st
	}

	// Reset if window expired from first step.
	if len(st.timestamps) > 0 && now.Sub(st.timestamps[0]) > window {
		st.stepsMatched = 0
		st.timestamps = st.timestamps[:0]
		if stepIndex != 0 {
			return false
		}
	}

	// Must match steps in order.
	if stepIndex != st.stepsMatched {
		return false
	}

	st.stepsMatched++
	st.timestamps = append(st.timestamps, now)
	st.lastSeen = now

	if st.stepsMatched >= totalSteps {
		// Full sequence matched — reset for next detection.
		st.stepsMatched = 0
		st.timestamps = st.timestamps[:0]
		return true
	}
	return false
}

// ResetCounter removes a specific counter (used after rollback/action).
func (c *Correlator) ResetCounter(ruleID, groupValue string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.counters, ruleID+":"+groupValue)
}

// Cleanup removes expired entries. Should be called periodically.
func (c *Correlator) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for key, cg := range c.counters {
		if now.Sub(cg.lastSeen) > cg.window*2 {
			delete(c.counters, key)
		}
	}

	for key, st := range c.sequences {
		if now.Sub(st.lastSeen) > st.window*2 {
			delete(c.sequences, key)
		}
	}
}

func (c *Correlator) evictCountersIfNeeded() {
	if len(c.counters) < c.maxGroups {
		return
	}
	// Evict oldest entry.
	var oldestKey string
	var oldestTime time.Time
	for k, v := range c.counters {
		if oldestKey == "" || v.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastSeen
		}
	}
	if oldestKey != "" {
		delete(c.counters, oldestKey)
	}
}

func (c *Correlator) evictSequencesIfNeeded() {
	if len(c.sequences) < c.maxGroups {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	for k, v := range c.sequences {
		if oldestKey == "" || v.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.lastSeen
		}
	}
	if oldestKey != "" {
		delete(c.sequences, oldestKey)
	}
}
