//go:build linux

package autonomy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/responder"
)

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

func (dr *DecisionReporter) report(d Decision) {
	payload, err := json.Marshal(d)
	if err != nil {
		slog.Warn("autonomy reporter: marshal failed", "err", err)
		return
	}

	commandID := fmt.Sprintf("decision-%s-%d", d.RuleID, d.Timestamp)
	if dr.reporter != nil {
		dr.reporter.Send(commandID, "autonomous_"+d.Action, string(payload))
	}
}
