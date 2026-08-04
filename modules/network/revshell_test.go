package network

import (
	"context"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Dial failures are reported as a (Success=true, Error=<detail>) event rather
// than a Generate error - "connection refused" is expected, valid telemetry
// when nothing is listening. Before the fix, net.Dial ignored ctx entirely,
// so an already-cancelled context still ran a real connect attempt and
// failed with "connection refused". net.Dialer.DialContext checks ctx.Err()
// before attempting anything, so a pre-cancelled context now short-circuits
// with a context error instead of ever reaching the network stack -
// verified directly (see scratch dialtest) that DialContext against an
// already-cancelled context never produces a "refused" error.
func TestNetRevShell_DialRespectsContext(t *testing.T) {
	n := &netRevShell{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := n.Generate(ctx, module.Params{"target": "127.0.0.1", "port": "1"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v, want nil (dial failures are reported via event)", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if strings.Contains(events[0].Error, "refused") {
		t.Errorf("dial reached the network despite an already-cancelled context: %q", events[0].Error)
	}
}

func TestNetRevShell_ConnectionRefusedIsReportedAsSuccess(t *testing.T) {
	n := &netRevShell{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	err := n.Generate(context.Background(), module.Params{"target": "127.0.0.1", "port": "1"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v, want nil", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Success {
		t.Errorf("event.Success = false, want true (connection refused is expected telemetry)")
	}
	if !strings.Contains(events[0].Error, "refused") {
		t.Errorf("event.Error = %q, want it to mention connection refused", events[0].Error)
	}
}
