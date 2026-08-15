package localrules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Detection represents a rule that fired on an event.
type Detection struct {
	Rule      *Rule
	Score     float64
	EventData map[string]interface{}
	Timestamp time.Time
	GroupKey  string // for correlation/sequence: the group_by value
}

// Engine evaluates events against the local rule set with resource budgets.
type Engine struct {
	store      *Store
	correlator *Correlator
	regexCache *regexCache

	// Protected by mu — written by Reload/SetProfileRefs, read by Evaluate.
	mu          sync.RWMutex
	compiled    []CompiledRule
	profileRefs map[string][]string

	// Atomic for lock-free read on hot path.
	degradeLevel atomic.Int32

	// Resource budgets (immutable after construction).
	maxRules       int
	budgetPerEvent time.Duration
}

// EngineConfig controls the resource budget of the local rule engine.
type EngineConfig struct {
	MaxRules             int
	BudgetPerEventMicros int64
	MaxCorrelationGroups int
	MaxCorrelationEvents int
	RegexCacheSize       int
}

// DefaultEngineConfig returns conservative defaults for a small host.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxRules:             50,
		BudgetPerEventMicros: 100,
		MaxCorrelationGroups: 1000,
		MaxCorrelationEvents: 10000,
		RegexCacheSize:       256,
	}
}

// NewEngine creates a local rule evaluation engine.
func NewEngine(store *Store, cfg EngineConfig) *Engine {
	e := &Engine{
		store:          store,
		correlator:     NewCorrelator(cfg.MaxCorrelationGroups, cfg.MaxCorrelationEvents),
		regexCache:     newRegexCache(cfg.RegexCacheSize),
		profileRefs:    make(map[string][]string),
		maxRules:       cfg.MaxRules,
		budgetPerEvent: time.Duration(cfg.BudgetPerEventMicros) * time.Microsecond,
	}
	e.recompile()
	return e
}

// SetDegradeLevel sets the current CPU pressure level (0-4).
// Called by the watchdog when resource pressure changes.
func (e *Engine) SetDegradeLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 4 {
		level = 4
	}
	e.degradeLevel.Store(int32(level))
}

// SetProfileRefs updates the resolved baseline references from the host profile.
func (e *Engine) SetProfileRefs(refs map[string][]string) {
	e.mu.Lock()
	e.profileRefs = refs
	e.mu.Unlock()
	e.recompile()
}

// Reload recompiles rules from the store. Call after store.Update().
func (e *Engine) Reload() {
	e.recompile()
}

// Evaluate checks a single event against all active rules within the time budget.
// Returns all detections (rules that fired).
func (e *Engine) Evaluate(event map[string]interface{}) []Detection {
	e.mu.RLock()
	compiled := e.compiled
	profileRefs := e.profileRefs
	e.mu.RUnlock()

	if len(compiled) == 0 {
		return nil
	}

	degradeLevel := int(e.degradeLevel.Load())
	deadline := time.Now().Add(e.budgetPerEvent)
	var detections []Detection

	for i := range compiled {
		if time.Now().After(deadline) {
			break
		}

		rule := &compiled[i]

		if !severityAllowedByDegradation(degradeLevel, rule.Severity) {
			continue
		}

		if det := e.evaluateRule(rule, event, profileRefs); det != nil {
			detections = append(detections, *det)
		}
	}

	return detections
}

// Correlator exposes the internal correlator for cleanup scheduling.
func (e *Engine) Correlator() *Correlator {
	return e.correlator
}

func (e *Engine) evaluateRule(cr *CompiledRule, event map[string]interface{}, refs map[string][]string) *Detection {
	// Simple rule (conditions on single event).
	if len(cr.Conditions) > 0 && cr.Correlation == nil && cr.Sequence == nil {
		return e.evaluateSimple(cr, event, refs)
	}

	// Correlation rule.
	if cr.Correlation != nil {
		return e.evaluateCorrelation(cr, event)
	}

	// Sequence rule.
	if cr.Sequence != nil {
		return e.evaluateSequence(cr, event, refs)
	}

	return nil
}

func (e *Engine) evaluateSimple(cr *CompiledRule, event map[string]interface{}, refs map[string][]string) *Detection {
	var totalScore float64

	for i, cc := range cr.compiledConditions {
		fieldVal := getField(event, cc.Field)
		if fieldVal == "" {
			continue
		}

		matched := false
		switch cc.Op {
		case "eq":
			if cc.hasStr {
				matched = fieldVal == cc.strVal
			}
		case "neq":
			if cc.hasStr {
				matched = fieldVal != cc.strVal
			}
		case "contains":
			if cc.hasStr {
				matched = strings.Contains(fieldVal, cc.strVal)
			}
		case "regex":
			if re, ok := cr.compiledPatterns[i]; ok {
				matched = re.MatchString(fieldVal)
			}
		case "in":
			if cc.inSet != nil {
				_, matched = cc.inSet[fieldVal]
			} else {
				matched = matchIn(fieldVal, cc.Value, refs)
			}
		case "not_in":
			if cc.inSet != nil {
				_, found := cc.inSet[fieldVal]
				matched = !found
			} else {
				matched = !matchIn(fieldVal, cc.Value, refs)
			}
		case "gt":
			if fv, tv, ok := parseNumericPair(fieldVal, cc.Value); ok {
				matched = fv > tv
			}
		case "lt":
			if fv, tv, ok := parseNumericPair(fieldVal, cc.Value); ok {
				matched = fv < tv
			}
		case "gte":
			if fv, tv, ok := parseNumericPair(fieldVal, cc.Value); ok {
				matched = fv >= tv
			}
		case "lte":
			if fv, tv, ok := parseNumericPair(fieldVal, cc.Value); ok {
				matched = fv <= tv
			}
		}

		if matched {
			totalScore += cc.Weight
		}
	}

	if totalScore >= cr.Threshold {
		return &Detection{
			Rule:      &cr.Rule,
			Score:     totalScore,
			EventData: event,
			Timestamp: time.Now(),
		}
	}
	return nil
}

func (e *Engine) evaluateCorrelation(cr *CompiledRule, event map[string]interface{}) *Detection {
	spec := cr.Correlation

	// Check event type matches.
	eventType := getField(event, "event_type")
	if eventType != spec.EventType {
		return nil
	}

	// Check additional conditions.
	for field, expected := range spec.Conditions {
		if getField(event, field) != expected {
			return nil
		}
	}

	groupValue := getField(event, spec.GroupBy)
	if groupValue == "" {
		groupValue = "_default"
	}

	if e.correlator.IncrementCounter(cr.ID, groupValue, spec.CountThreshold, spec.TimeframeSec) {
		e.correlator.ResetCounter(cr.ID, groupValue)
		return &Detection{
			Rule:      &cr.Rule,
			Score:     cr.Threshold,
			EventData: event,
			Timestamp: time.Now(),
			GroupKey:  groupValue,
		}
	}
	return nil
}

func (e *Engine) evaluateSequence(cr *CompiledRule, event map[string]interface{}, refs map[string][]string) *Detection {
	spec := cr.Sequence
	eventType := getField(event, "event_type")

	groupValue := getField(event, spec.GroupBy)
	if groupValue == "" {
		groupValue = "_default"
	}

	// Find which step(s) this event could match.
	for stepIdx, step := range spec.Steps {
		if eventType != step.EventType {
			continue
		}

		// Check field matches for this step.
		allMatch := true
		for field, expected := range step.FieldMatch {
			fieldVal := getField(event, field)
			if ref, ok := expected.(map[string]interface{}); ok {
				if refName, ok := ref["ref"].(string); ok {
					if !matchInList(fieldVal, refName, refs) {
						allMatch = false
						break
					}
					continue
				}
			}
			if expectedStr, ok := expected.(string); ok {
				if fieldVal != expectedStr {
					allMatch = false
					break
				}
			}
		}

		if !allMatch {
			continue
		}

		if e.correlator.AdvanceSequence(cr.ID, groupValue, stepIdx, len(spec.Steps), spec.TimeframeSec) {
			return &Detection{
				Rule:      &cr.Rule,
				Score:     cr.Threshold,
				EventData: event,
				Timestamp: time.Now(),
				GroupKey:  groupValue,
			}
		}
	}
	return nil
}

func parseNumericPair(fieldVal string, condValue interface{}) (float64, float64, bool) {
	fv, err := strconv.ParseFloat(fieldVal, 64)
	if err != nil {
		return 0, 0, false
	}
	switch v := condValue.(type) {
	case float64:
		return fv, v, true
	case json.Number:
		tv, err := v.Float64()
		if err != nil {
			return 0, 0, false
		}
		return fv, tv, true
	case string:
		tv, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, 0, false
		}
		return fv, tv, true
	case int:
		return fv, float64(v), true
	case int64:
		return fv, float64(v), true
	}
	return 0, 0, false
}

func matchIn(val string, condValue interface{}, refs map[string][]string) bool {
	// Check if it's a profile reference.
	if m, ok := condValue.(map[string]interface{}); ok {
		if ref, ok := m["ref"].(string); ok {
			return matchInList(val, ref, refs)
		}
	}

	// Direct list of values.
	switch v := condValue.(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == val {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == val {
				return true
			}
		}
	}
	return false
}

func matchInList(val, refName string, refs map[string][]string) bool {
	list, ok := refs[refName]
	if !ok {
		return false
	}
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func severityAllowedByDegradation(level int, severity string) bool {
	switch level {
	case 0:
		return true
	case 1:
		return severity != SeverityLow
	case 2:
		return severity == SeverityCritical || severity == SeverityHigh
	case 3:
		return severity == SeverityCritical || severity == SeverityHigh
	case 4:
		return severity == SeverityCritical
	default:
		return severity == SeverityCritical
	}
}

func (e *Engine) recompile() {
	rs := e.store.Current()
	if rs == nil {
		e.mu.Lock()
		e.compiled = nil
		e.mu.Unlock()
		return
	}

	// Work on a copy of the rules slice to avoid mutating the store's data.
	rules := make([]Rule, len(rs.Rules))
	copy(rules, rs.Rules)

	if len(rules) > e.maxRules {
		sort.Slice(rules, func(i, j int) bool {
			return SeverityPriority(rules[i].Severity) < SeverityPriority(rules[j].Severity)
		})
		rules = rules[:e.maxRules]
	}

	sort.Slice(rules, func(i, j int) bool {
		return SeverityPriority(rules[i].Severity) < SeverityPriority(rules[j].Severity)
	})

	compiled := CompileRules(rules, e.regexCache)

	e.mu.Lock()
	e.compiled = compiled
	e.mu.Unlock()
}

// getField extracts a string value from a nested event map using dot notation.
// Fast path for simple (non-nested) fields avoids strings.Split allocation.
func getField(event map[string]interface{}, field string) string {
	if !strings.ContainsRune(field, '.') {
		return fieldToString(event[field])
	}
	parts := strings.Split(field, ".")
	var current interface{} = event
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current = m[part]
	}
	return fieldToString(current)
}

func fieldToString(v interface{}) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
}

