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
	RuleType   string  `json:"rule_type"` // "anomaly" | "surveillance"
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

// CompiledCondition is a Condition with values pre-extracted at compile time
// to avoid repeated type assertions and map allocations on the hot path.
type CompiledCondition struct {
	Condition
	strVal string            // pre-extracted for op ∈ {eq, neq, contains}
	hasStr bool              // true if strVal is valid
	inSet  map[string]struct{} // pre-built O(1) set for op ∈ {in, not_in} on static lists
}

// CompiledRule is a Rule with pre-compiled regex patterns and pre-extracted
// condition values for fast evaluation.
type CompiledRule struct {
	Rule
	compiledPatterns   map[int]*regexp.Regexp
	compiledConditions []CompiledCondition
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

// CompileRules pre-compiles regex patterns and pre-extracts condition values.
func CompileRules(rules []Rule, cache *regexCache) []CompiledRule {
	compiled := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr := CompiledRule{
			Rule:               r,
			compiledPatterns:   make(map[int]*regexp.Regexp),
			compiledConditions: make([]CompiledCondition, len(r.Conditions)),
		}
		for i, cond := range r.Conditions {
			cc := CompiledCondition{Condition: cond}
			switch cond.Op {
			case "eq", "neq", "contains":
				if s, ok := cond.Value.(string); ok {
					cc.strVal = s
					cc.hasStr = true
				}
			case "regex":
				if pattern, ok := cond.Value.(string); ok {
					if re, err := cache.get(pattern); err == nil {
						cr.compiledPatterns[i] = re
					}
				}
			case "in", "not_in":
				cc.inSet = buildInSet(cond.Value)
			}
			cr.compiledConditions[i] = cc
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

// buildInSet converts a static list value into an O(1) lookup set.
// Returns nil for profile references ({"ref": ...}) — those stay dynamic.
func buildInSet(value interface{}) map[string]struct{} {
	switch v := value.(type) {
	case []interface{}:
		// Skip if it's a profile reference.
		if len(v) == 1 {
			if m, ok := v[0].(map[string]interface{}); ok {
				if _, isRef := m["ref"]; isRef {
					return nil
				}
			}
		}
		set := make(map[string]struct{}, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				set[s] = struct{}{}
			}
		}
		return set
	case []string:
		set := make(map[string]struct{}, len(v))
		for _, s := range v {
			set[s] = struct{}{}
		}
		return set
	case map[string]interface{}:
		// Profile reference — keep dynamic.
		return nil
	}
	return nil
}
