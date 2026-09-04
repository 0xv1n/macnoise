//go:build !windows

package process

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Excluded on Windows for the same reason as es_process's exec test: Go's
// os/exec there routes through an MSYS2/Cygwin sh that re-parses the command
// line unlike real POSIX sh, which is not this module's target. CI runs this on
// Linux, and it runs on the mini.
func TestSpawnGenerate_EmitsSuccess(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	err := (&procSpawn{}).Generate(context.Background(), module.Params{"command": "echo macnoise-spawn-test"}, emit)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 1 || events[0].EventType != "process_spawn" {
		t.Fatalf("expected 1 process_spawn event, got %+v", events)
	}
	if !events[0].Success {
		t.Errorf("spawn of a plain echo should succeed: %s", events[0].Message)
	}
	if out, _ := events[0].Details["output"].(string); !strings.Contains(out, "macnoise-spawn-test") {
		t.Errorf("captured output %q should contain the echoed text", out)
	}
}

func TestSpawnGenerate_RunIDInCommand(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	ctx := module.ContextWithRunID(context.Background(), "spawnrun42")
	if err := (&procSpawn{}).Generate(ctx, module.Params{"command": "echo hi"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cmd, _ := events[0].Details["command"].(string)
	if !strings.Contains(cmd, "# mn:spawnrun42") {
		t.Errorf("spawned command %q should carry the run ID comment", cmd)
	}
}
