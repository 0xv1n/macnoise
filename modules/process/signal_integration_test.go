//go:build integration && darwin

package process

import (
	"context"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Forks a real short-lived process and signals it: the module must emit a
// process_fork followed by a signal_send per signal, and fold the run ID into
// the forked command's argv.
func TestSignalGenerate_ForkThenSignals(t *testing.T) {
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	ctx := module.ContextWithRunID(context.Background(), "sigrun3")
	if err := (&procSignal{}).Generate(ctx, module.Params{"target_command": "sleep 2"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) == 0 || events[0].EventType != "process_fork" {
		t.Fatalf("first event should be process_fork, got %+v", events)
	}
	if !events[0].Success {
		t.Fatalf("fork failed: %s", events[0].Message)
	}

	cmd, _ := events[0].Details["command"].(string)
	if !strings.Contains(cmd, "# mn:sigrun3") {
		t.Errorf("forked command %q should carry the run ID comment # mn:sigrun3", cmd)
	}

	var signalSends int
	for _, ev := range events[1:] {
		if ev.EventType == "signal_send" {
			signalSends++
		}
	}
	if signalSends != 3 {
		t.Errorf("emitted %d signal_send events, want 3 (SIGSTOP, SIGCONT, SIGTERM)", signalSends)
	}
}
