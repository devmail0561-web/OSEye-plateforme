//go:build linux

package policy

import (
	"encoding/json"
	"testing"

	gen "github.com/devmail0561-web/OSEye-plateforme/agent/gen"
	"github.com/devmail0561-web/OSEye-plateforme/agent/internal/collector"
)

func TestApplyStoresCurrent(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	h := NewHandler(mgr)
	cfg, _ := json.Marshal(map[string]interface{}{"throttle": 0.5})
	p := &gen.SurveillanceProfilePB{Name: "baseline", Version: 3, ConfigJson: cfg}

	h.Apply(p)
	cur := h.Current()
	if cur == nil || cur.GetName() != "baseline" || cur.GetVersion() != 3 {
		t.Fatalf("Current() = %v, want baseline v3", cur)
	}
}

func TestApplyInvalidJSON(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	h := NewHandler(mgr)
	p := &gen.SurveillanceProfilePB{Name: "broken", ConfigJson: []byte("{not json")}
	h.Apply(p) // must not panic
	if h.Current() == nil || h.Current().GetName() != "broken" {
		t.Fatal("profile should still be stored even with invalid config")
	}
}

func TestApplyNilConfig(t *testing.T) {
	mgr := collector.NewManager(nil, 4)
	h := NewHandler(mgr)
	p := &gen.SurveillanceProfilePB{Name: "empty"}
	h.Apply(p)
	if h.Current() == nil {
		t.Fatal("expected profile stored")
	}
}

func TestToFloatCoercion(t *testing.T) {
	if f, ok := toFloat(float64(0.25)); !ok || f != 0.25 {
		t.Errorf("toFloat(float64) failed")
	}
	if f, ok := toFloat(3); !ok || f != 3 {
		t.Errorf("toFloat(int) failed")
	}
	if _, ok := toFloat("nope"); ok {
		t.Errorf("toFloat(string) should be false")
	}
}
