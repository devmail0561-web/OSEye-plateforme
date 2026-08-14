package hostprofile

import (
	"encoding/json"
	"testing"
)

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p.Name != "default" {
		t.Errorf("expected name 'default', got %q", p.Name)
	}
	if p.Autonomy != "critical_only" {
		t.Errorf("expected autonomy 'critical_only', got %q", p.Autonomy)
	}
	if p.Budget.MaxRules != 50 {
		t.Errorf("expected MaxRules 50, got %d", p.Budget.MaxRules)
	}
}

func TestProfileStoreUpdateAndPersist(t *testing.T) {
	dir := t.TempDir()

	store, err := NewProfileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	profile := &Profile{
		Name:         "web-server",
		Version:      3,
		Role:         "web",
		Autonomy:     "always_act",
		BaselineApps: []string{"/usr/sbin/nginx", "/usr/bin/postgres"},
		Budget: ResourceBudget{
			MaxRules:             200,
			CPUBudgetPct:         2.0,
			BufferMB:             500,
			BatchSize:            3000,
			BudgetPerEventMicros: 200,
			MaxCorrelationGroups: 2000,
			MaxCorrelationEvents: 20000,
		},
	}

	data, _ := json.Marshal(profile)
	if err := store.Update(data); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	current := store.Current()
	if current.Name != "web-server" {
		t.Errorf("expected name web-server, got %q", current.Name)
	}
	if current.Budget.MaxRules != 200 {
		t.Errorf("expected MaxRules 200, got %d", current.Budget.MaxRules)
	}

	// Reopen and verify persistence.
	store2, err := NewProfileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	persisted := store2.Current()
	if persisted.Name != "web-server" {
		t.Errorf("expected persisted name web-server, got %q", persisted.Name)
	}
	if persisted.Version != 3 {
		t.Errorf("expected persisted version 3, got %d", persisted.Version)
	}
}

func TestProfileBaselineRefs(t *testing.T) {
	p := &Profile{
		BaselineApps:     []string{"/usr/sbin/nginx", "/usr/bin/postgres"},
		BaselineNetDests: []string{"10.0.0.0/8"},
		BaselinePorts:    []int{80, 443},
		BaselineUsers:    []string{"root", "deploy"},
		SetuidBinaries:   []string{"/usr/bin/sudo"},
	}

	refs := p.BaselineRefs()

	if len(refs["baseline_apps"]) != 2 {
		t.Errorf("expected 2 baseline_apps, got %d", len(refs["baseline_apps"]))
	}
	if refs["baseline_ports"][0] != "80" {
		t.Errorf("expected port '80', got %q", refs["baseline_ports"][0])
	}
	if refs["setuid_binaries"][0] != "/usr/bin/sudo" {
		t.Errorf("expected sudo in setuid_binaries")
	}
}
