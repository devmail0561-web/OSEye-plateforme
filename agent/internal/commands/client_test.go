package commands

import (
	"encoding/json"
	"testing"

	gen "github.com/oseye/agent/gen"
	"github.com/oseye/agent/internal/collector"
)

func TestDispatchUnknownCommand(t *testing.T) {
	c := &CommandClient{mgr: collector.NewManager(nil, 4)}
	c.dispatch(&gen.AgentCommand{CommandType: "BOGUS"}) // must not panic
}

func TestDispatchSetThrottleInvalidPayload(t *testing.T) {
	c := &CommandClient{mgr: collector.NewManager(nil, 4)}
	c.dispatch(&gen.AgentCommand{CommandType: cmdSetThrottle, PayloadJson: []byte("not json")}) // no panic
}

func TestDispatchActionsNoPanic(t *testing.T) {
	c := &CommandClient{mgr: collector.NewManager(nil, 4)}
	fac := map[string]interface{}{"factor": 0.5}
	raw, _ := json.Marshal(fac)
	c.dispatch(&gen.AgentCommand{CommandType: cmdSetThrottle, PayloadJson: raw})
	c.dispatch(&gen.AgentCommand{CommandType: cmdReloadProfile})
	c.dispatch(&gen.AgentCommand{CommandType: cmdTakeSnapshot})
}
