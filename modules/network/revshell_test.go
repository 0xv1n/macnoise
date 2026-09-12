package network

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Cancellation must return its error without inventing a network denial.
func TestNetRevShell_DialRespectsContext(t *testing.T) {
	n := &netRevShell{}
	var events []module.TelemetryEvent
	emit := captureNetworkEvents(&events)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := n.Generate(ctx, module.Params{"target": "127.0.0.1", "port": "1"}, emit)
	if !errors.Is(err, context.Canceled) || len(events) != 0 {
		t.Fatalf("Generate = %v, events = %+v; want cancellation without events", err, events)
	}
}

func TestNetRevShell_ConnectionRefusedIsReportedAsDenied(t *testing.T) {
	n := &netRevShell{}
	var events []module.TelemetryEvent
	emit := captureNetworkEvents(&events)

	err := n.Generate(context.Background(), module.Params{"target": "127.0.0.1", "port": "1"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v, want nil", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Outcome != module.OutcomeDenied {
		t.Errorf("event.Outcome = %q, want denied", events[0].Outcome)
	}
	if !strings.Contains(events[0].Error, "refused") {
		t.Errorf("event.Error = %q, want it to mention connection refused", events[0].Error)
	}
}
