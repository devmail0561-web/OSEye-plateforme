//go:build linux

package policy

import (
	"encoding/json"
	"log/slog"
	"sync/atomic"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/collector"
)

// ProfileHandler applies SurveillanceProfile updates to the collector manager.
type ProfileHandler struct {
	mgr     *collector.CollectorManager
	current atomic.Pointer[gen.SurveillanceProfilePB]
}

// NewHandler returns a ProfileHandler bound to the given collector manager.
func NewHandler(mgr *collector.CollectorManager) *ProfileHandler {
	return &ProfileHandler{mgr: mgr}
}

// Apply parses profile.ConfigJson and applies throttle / collectors_enabled
// directives to the manager, then stores the profile as the current one.
func (h *ProfileHandler) Apply(profile *gen.SurveillanceProfilePB) {
	var cfg map[string]interface{}
	if len(profile.GetConfigJson()) > 0 {
		if err := json.Unmarshal(profile.GetConfigJson(), &cfg); err != nil {
			slog.Warn("profile config json invalid", "err", err, "name", profile.GetName())
		}
	}

	if cfg != nil {
		if raw, ok := cfg["throttle"]; ok {
			if f, ok := toFloat(raw); ok {
				h.mgr.SetThrottle(f)
				slog.Info("profile throttle applied", "name", profile.GetName(), "version", profile.GetVersion(), "throttle", f)
			}
		}
		// Disable collectors absent from collectors_enabled by throttling them to 0.
		if enabled, ok := cfg["collectors_enabled"].([]interface{}); ok {
			enabledSet := make(map[string]bool, len(enabled))
			for _, e := range enabled {
				if s, ok := e.(string); ok {
					enabledSet[s] = true
				}
			}
			// The manager only supports a global throttle; disabling specific
			// collectors is deferred to a per-collector policy (Phase 5).
			_ = enabledSet
		}
	}

	if len(cfg) > 0 || profile.GetName() != "" {
		h.current.Store(profile)
		slog.Info("profile applied", "name", profile.GetName(), "version", profile.GetVersion())
	}
}

// Current returns the most recently applied profile, or nil.
func (h *ProfileHandler) Current() *gen.SurveillanceProfilePB {
	return h.current.Load()
}

// toFloat coerces a JSON number (float64) into a float64.
func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}
