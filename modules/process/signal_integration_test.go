//go:build integration && darwin

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Forks a real short-lived process and signals it: the module must emit a
// process_fork followed by a signal_send per signal, and fold the run ID into
// the forked command's argv.
func TestSignalGenerate_ForkThenSignals(t *testing.T) {
	var events []module.TelemetryEvent
	emit := captureProcessEvents(&events)
	ctx := module.ContextWithRunID(context.Background(), "sigrun3")
	if err := (&procSignal{}).Generate(ctx, module.Params{"target_command": "sleep 2"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) == 0 || events[0].EventType != "process_fork" {
		t.Fatalf("first event should be process_fork, got %+v", events)
	}
	if events[0].Outcome != module.OutcomeExecuted {
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

func TestSignalGenerate_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalEvents := 0
	err := (&procSignal{}).Generate(ctx, module.Params{"target_command": "sleep 30"}, func(event module.TelemetryEvent) error {
		switch event.EventType {
		case "process_fork":
			cancel()
		case "signal_send":
			signalEvents++
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want context.Canceled", err)
	}
	if signalEvents != 0 {
		t.Fatalf("emitted %d signal events after cancellation", signalEvents)
	}
}

func TestSignalGenerate_CleansUpDescendants(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-ran")
	command := fmt.Sprintf("(sleep 1; touch %q) & wait", marker)
	if err := (&procSignal{}).Generate(context.Background(), module.Params{"target_command": command}, func(module.TelemetryEvent) error {
		return nil
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("descendant survived Generate cleanup: %v", err)
	}
}
