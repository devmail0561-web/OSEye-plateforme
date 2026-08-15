package hostprofile

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Profile holds the host profile pushed by the server, including baselines,
// autonomy policy, and resource budgets.
type Profile struct {
	Name     string `json:"name"`
	Version  int64  `json:"version"`
	Role     string `json:"role"`
	Autonomy string `json:"autonomy"` // always_act, critical_high, critical_only, log_only

	// Baselines resolved by the server.
	BaselineApps     []string `json:"baseline_apps"`
	BaselineNetDests []string `json:"baseline_net_dests"`
	BaselinePorts    []int    `json:"baseline_ports"`
	BaselineUsers    []string `json:"baseline_users"`
	SetuidBinaries   []string `json:"setuid_binaries"`

	// Resource budgets calculated by server from host specs.
	Budget ResourceBudget `json:"budget"`

	// portsStr is BaselinePorts pre-converted to strings, cached at parse time.
	// Not serialized — recomputed in setDerivedFields after every unmarshal.
	portsStr []string
}

// ResourceBudget defines the resource limits for the local rule engine.
type ResourceBudget struct {
	MaxRules             int     `json:"max_rules"`
	CPUBudgetPct         float64 `json:"cpu_budget_pct"`
	BufferMB             int     `json:"buffer_mb"`
	BatchSize            int     `json:"batch_size"`
	BudgetPerEventMicros int64   `json:"budget_per_event_micros"`
	MaxCorrelationGroups int     `json:"max_correlation_groups"`
	MaxCorrelationEvents int     `json:"max_correlation_events"`
}

// DefaultProfile returns a minimal profile for when no server profile has been received.
func DefaultProfile() *Profile {
	return &Profile{
		Name:     "default",
		Version:  0,
		Role:     "unknown",
		Autonomy: "critical_only",
		Budget: ResourceBudget{
			MaxRules:             50,
			CPUBudgetPct:         1.0,
			BufferMB:             50,
			BatchSize:            1000,
			BudgetPerEventMicros: 100,
			MaxCorrelationGroups: 1000,
			MaxCorrelationEvents: 10000,
		},
	}
}

// BaselineRefs returns all baselines as a map for the rule engine's ref resolution.
// BaselinePorts are pre-converted to strings in setDerivedFields to avoid
// repeated fmt.Sprintf calls on the hot path.
func (p *Profile) BaselineRefs() map[string][]string {
	refs := make(map[string][]string, 5)
	if len(p.BaselineApps) > 0 {
		refs["baseline_apps"] = p.BaselineApps
	}
	if len(p.BaselineNetDests) > 0 {
		refs["baseline_net_dests"] = p.BaselineNetDests
	}
	if len(p.BaselineUsers) > 0 {
		refs["baseline_users"] = p.BaselineUsers
	}
	if len(p.SetuidBinaries) > 0 {
		refs["setuid_binaries"] = p.SetuidBinaries
	}
	if len(p.portsStr) > 0 {
		refs["baseline_ports"] = p.portsStr
	} else if len(p.BaselinePorts) > 0 {
		ports := make([]string, len(p.BaselinePorts))
		for i, port := range p.BaselinePorts {
			ports[i] = strconv.Itoa(port)
		}
		refs["baseline_ports"] = ports
	}
	return refs
}

// setDerivedFields precomputes fields that are expensive to recompute on every call.
// Must be called after any json.Unmarshal into a Profile.
func setDerivedFields(p *Profile) {
	if len(p.BaselinePorts) > 0 {
		ports := make([]string, len(p.BaselinePorts))
		for i, port := range p.BaselinePorts {
			ports[i] = strconv.Itoa(port)
		}
		p.portsStr = ports
	}
}

// ProfileStore persists the host profile locally so it survives restarts.
type ProfileStore struct {
	mu      sync.RWMutex
	dir     string
	current *Profile
}

const profileFileName = "host_profile.json"

// NewProfileStore opens or creates the profile store at the given directory.
func NewProfileStore(dir string) (*ProfileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("hostprofile: mkdir: %w", err)
	}

	ps := &ProfileStore{dir: dir}

	// Load existing profile from disk.
	path := filepath.Join(dir, profileFileName)
	if data, err := os.ReadFile(path); err == nil {
		var p Profile
		if err := json.Unmarshal(data, &p); err == nil {
			setDerivedFields(&p)
			ps.current = &p
			slog.Info("hostprofile: loaded from disk", "name", p.Name, "version", p.Version)
		}
	}

	if ps.current == nil {
		ps.current = DefaultProfile()
	}

	return ps, nil
}

// Update replaces the current profile with a new one from the server.
func (ps *ProfileStore) Update(data []byte) error {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("hostprofile: parse profile: %w", err)
	}

	setDerivedFields(&p)

	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.current = &p

	// Persist to disk.
	path := filepath.Join(ps.dir, profileFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		slog.Warn("hostprofile: failed to persist profile", "err", err)
	}

	slog.Info("hostprofile: profile updated", "name", p.Name, "version", p.Version, "autonomy", p.Autonomy)
	return nil
}

// Current returns a shallow copy of the active profile.
func (ps *ProfileStore) Current() *Profile {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if ps.current == nil {
		return DefaultProfile()
	}
	cp := *ps.current
	return &cp
}
