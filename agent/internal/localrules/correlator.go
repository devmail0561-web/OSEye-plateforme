package localrules

import (
	"sync"
	"time"
)

// Correlator tracks event counts and sequences within time windows for
// correlation and sequence rules. Memory is bounded by maxGroups and maxEvents.
//
// Two-level maps (ruleID → groupValue → state) eliminate per-event string
// concatenation compared to a flat "ruleID:groupValue" key scheme.
type Correlator struct {
	mu        sync.Mutex
	counters  map[string]map[string]*counterGroup
	sequences map[string]map[string]*sequenceTracker
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
		counters:  make(map[string]map[string]*counterGroup, 64),
		sequences: make(map[string]map[string]*sequenceTracker, 64),
		maxGroups: maxGroups,
		maxEvents: maxEvents,
	}
}

// IncrementCounter adds an event to a correlation counter and returns true if
// the count threshold has been reached within the time window.
func (c *Correlator) IncrementCounter(ruleID, groupValue string, threshold int, windowSec int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	window := time.Duration(windowSec) * time.Second

	inner, ok := c.counters[ruleID]
	if !ok {
		inner = make(map[string]*counterGroup)
		c.counters[ruleID] = inner
	}

	cg, ok := inner[groupValue]
	if !ok {
		c.evictCountersIfNeeded()
		cg = &counterGroup{
			count:     0,
			firstSeen: now,
			lastSeen:  now,
			window:    window,
		}
		inner[groupValue] = cg
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

	now := time.Now()
	window := time.Duration(windowSec) * time.Second

	inner, ok := c.sequences[ruleID]
	if !ok {
		if stepIndex != 0 {
			return false
		}
		inner = make(map[string]*sequenceTracker)
		c.sequences[ruleID] = inner
	}

	st, ok := inner[groupValue]
	if !ok {
		if stepIndex != 0 {
			return false
		}
		c.evictSequencesIfNeeded()
		st = &sequenceTracker{
			stepsMatched: 0,
			timestamps:   make([]time.Time, 0, totalSteps),
			window:       window,
		}
		inner[groupValue] = st
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
	if inner, ok := c.counters[ruleID]; ok {
		delete(inner, groupValue)
	}
}

// Cleanup removes expired entries. Should be called periodically.
func (c *Correlator) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for ruleID, inner := range c.counters {
		for groupValue, cg := range inner {
			if now.Sub(cg.lastSeen) > cg.window*2 {
				delete(inner, groupValue)
			}
		}
		if len(inner) == 0 {
			delete(c.counters, ruleID)
		}
	}

	for ruleID, inner := range c.sequences {
		for groupValue, st := range inner {
			if now.Sub(st.lastSeen) > st.window*2 {
				delete(inner, groupValue)
			}
		}
		if len(inner) == 0 {
			delete(c.sequences, ruleID)
		}
	}
}

// totalCounterEntries returns the total number of group entries across all rules.
func (c *Correlator) totalCounterEntries() int {
	n := 0
	for _, inner := range c.counters {
		n += len(inner)
	}
	return n
}

func (c *Correlator) evictCountersIfNeeded() {
	if c.totalCounterEntries() < c.maxGroups {
		return
	}
	var oldestRuleID, oldestGroupValue string
	var oldestTime time.Time
	for ruleID, inner := range c.counters {
		for gv, cg := range inner {
			if oldestRuleID == "" || cg.lastSeen.Before(oldestTime) {
				oldestRuleID = ruleID
				oldestGroupValue = gv
				oldestTime = cg.lastSeen
			}
		}
	}
	if oldestRuleID != "" {
		delete(c.counters[oldestRuleID], oldestGroupValue)
	}
}

// totalSequenceEntries returns the total number of sequence tracker entries.
func (c *Correlator) totalSequenceEntries() int {
	n := 0
	for _, inner := range c.sequences {
		n += len(inner)
	}
	return n
}

func (c *Correlator) evictSequencesIfNeeded() {
	if c.totalSequenceEntries() < c.maxGroups {
		return
	}
	var oldestRuleID, oldestGroupValue string
	var oldestTime time.Time
	for ruleID, inner := range c.sequences {
		for gv, st := range inner {
			if oldestRuleID == "" || st.lastSeen.Before(oldestTime) {
				oldestRuleID = ruleID
				oldestGroupValue = gv
				oldestTime = st.lastSeen
			}
		}
	}
	if oldestRuleID != "" {
		delete(c.sequences[oldestRuleID], oldestGroupValue)
	}
}
