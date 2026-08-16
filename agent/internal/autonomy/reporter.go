//go:build linux

package autonomy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/responder"
)

// decisionPayload is the minimal payload sent to the server for a decision.
// It deliberately excludes EventData to avoid exfiltrating raw event fields.
type decisionPayload struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	Timestamp time.Time `json:"timestamp"`
	RuleID    string    `json:"rule_id"`
	Action    string    `json:"action"`
}

// DecisionReporter consumes the decision log from the controller and reports
// autonomous decisions to the server via the existing Reporter.
type DecisionReporter struct {
	decisions <-chan Decision
	reporter  *responder.Reporter
	svc       gen.AgentServiceClient
	agentID   []byte
}

// NewDecisionReporter creates a reporter that forwards autonomous decisions.
func NewDecisionReporter(decisions <-chan Decision, reporter *responder.Reporter, svc gen.AgentServiceClient, agentID []byte) *DecisionReporter {
	return &DecisionReporter{
		decisions: decisions,
		reporter:  reporter,
		svc:       svc,
		agentID:   agentID,
	}
}

// Run processes decisions until ctx is cancelled.
func (dr *DecisionReporter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case d, ok := <-dr.decisions:
			if !ok {
				return
			}
			dr.report(d)
		}
	}
}

// strFromMap extracts a string value from a map[string]interface{} by key,
// returning an empty string if the key is absent or the value is not a string.
func strFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (dr *DecisionReporter) report(d Decision) {
	// Build a minimal payload — never forward EventData to avoid exfiltration.
	dp := decisionPayload{
		EventID:   strFromMap(d.EventData, "event_id"),
		EventType: strFromMap(d.EventData, "type"),
		Timestamp: time.Unix(0, d.Timestamp),
		RuleID:    d.RuleID,
		Action:    d.Action,
	}

	payload, err := json.Marshal(dp)
	if err != nil {
		slog.Warn("autonomy reporter: marshal failed", "err", err)
		return
	}

	// Use crypto/rand for an unpredictable command ID.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Warn("autonomy reporter: rand.Read failed", "err", err)
		return
	}
	commandID := hex.EncodeToString(b)

	if dr.reporter != nil {
		dr.reporter.Send(commandID, "autonomous_"+d.Action, string(payload))
	}
}
