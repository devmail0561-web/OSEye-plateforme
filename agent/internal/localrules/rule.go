package localrules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
)

// Severity levels ordered by priority.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// AutonomyLevel defines what the agent is allowed to do.
const (
	AutonomyAlwaysAct   = "always_act"
	AutonomyCriticalHigh = "critical_high"
	AutonomyCriticalOnly = "critical_only"
	AutonomyLogOnly     = "log_only"
)

// ResponseType is the action to take when a rule fires.
const (
	ResponseKillProcess    = "kill_process"
	ResponseBlockIP        = "block_ip"
	ResponseQuarantineFile = "quarantine_file"
	ResponseLog            = "log"
)

// Rule is the unified rule format evaluated locally by the agent.
type Rule struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Version    int     `json:"version"`
	Severity   string  `json:"severity"`
	Autonomy   string  `json:"autonomy"`
	Threshold  float64 `json:"threshold"`
	Response   string  `json:"response"`
	Confidence float64 `json:"confidence"`

	// Simple rule: conditions on a single event.
	Conditions []Condition `json:"conditions,omitempty"`

	// Correlation rule: counting events over a time window.
	Correlation *CorrelationSpec `json:"correlation,omitempty"`

	// Sequence rule: ordered chain of event types.
	Sequence *SequenceSpec `json:"sequence,omitempty"`
}

// Condition is a single field match with a weight.
type Condition struct {
	Field  string      `json:"field"`
	Op     string      `json:"op"`
	Value  interface{} `json:"value"`
	Weight float64     `json:"weight"`
}

// RefValue is used when value is a profile reference like {"ref": "baseline_apps"}.
type RefValue struct {
	Ref string `json:"ref"`
}

// CorrelationSpec defines a counting correlation rule.
type CorrelationSpec struct {
	EventType      string            `json:"event_type"`
	GroupBy        string            `json:"group_by"`
	CountThreshold int               `json:"count_threshold"`
	TimeframeSec   int               `json:"timeframe_seconds"`
	Conditions     map[string]string `json:"conditions,omitempty"`
}

// SequenceSpec defines an ordered sequence rule.
type SequenceSpec struct {
	TimeframeSec int            `json:"timeframe_seconds"`
	Steps        []SequenceStep `json:"steps"`
	GroupBy      string         `json:"group_by"`
}

// SequenceStep is one step in a sequence rule.
type SequenceStep struct {
	EventType  string            `json:"event_type"`
	FieldMatch map[string]interface{} `json:"field_match"`
}

// RuleSet is a versioned, signed collection of rules.
type RuleSet struct {
	Version   int64  `json:"version"`
	Rules     []Rule `json:"rules"`
	Signature []byte `json:"signature"`
}

// SeverityPriority returns a numeric priority for sorting (lower = more important).
func SeverityPriority(sev string) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

// IsActionAllowed returns whether the autonomy policy permits action for the given rule severity.
func IsActionAllowed(policy, severity string) bool {
	switch policy {
	case AutonomyAlwaysAct:
		return true
	case AutonomyCriticalHigh:
		return severity == SeverityCritical || severity == SeverityHigh
	case AutonomyCriticalOnly:
		return severity == SeverityCritical
	case AutonomyLogOnly:
		return false
	default:
		return false
	}
}

// ParseRuleSet unmarshals a JSON rule set.
func ParseRuleSet(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("localrules: parse ruleset: %w", err)
	}
	return &rs, nil
}

// CompiledRule is a Rule with pre-compiled regex patterns for fast evaluation.
type CompiledRule struct {
	Rule
	compiledPatterns map[int]*regexp.Regexp // condition index → compiled regex
}

// regexCache is a bounded LRU cache for compiled regex patterns.
type regexCache struct {
	mu      sync.Mutex
	entries map[string]*regexp.Regexp
	maxSize int
}

func newRegexCache(maxSize int) *regexCache {
	return &regexCache{
		entries: make(map[string]*regexp.Regexp, maxSize),
		maxSize: maxSize,
	}
}

func (c *regexCache) get(pattern string) (*regexp.Regexp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if re, ok := c.entries[pattern]; ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	if len(c.entries) >= c.maxSize {
		// Evict one entry (simple random eviction for bounded cache).
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[pattern] = re
	return re, nil
}

// CompileRules pre-compiles all regex patterns in the rule set.
func CompileRules(rules []Rule, cache *regexCache) []CompiledRule {
	compiled := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr := CompiledRule{
			Rule:             r,
			compiledPatterns: make(map[int]*regexp.Regexp),
		}
		for i, cond := range r.Conditions {
			if cond.Op == "regex" {
				if pattern, ok := cond.Value.(string); ok {
					if re, err := cache.get(pattern); err == nil {
						cr.compiledPatterns[i] = re
					}
				}
			}
		}
		compiled = append(compiled, cr)
	}
	return compiled
}
