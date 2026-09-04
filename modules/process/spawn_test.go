package process

import (
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestStampCommand_WithRunID(t *testing.T) {
	cmd := stampCommand("echo hi", "deadbeef01234567")
	if !strings.Contains(cmd, "deadbeef01234567") {
		t.Errorf("run ID missing from command: %s", cmd)
	}
	if !strings.HasPrefix(cmd, "echo hi") {
		t.Errorf("original command not preserved: %s", cmd)
	}
	if !strings.Contains(cmd, "#") {
		t.Errorf("run ID should be a shell comment: %s", cmd)
	}
}

func TestStampCommand_WithoutRunID(t *testing.T) {
	cmd := stampCommand("echo hi", "")
	if cmd != "echo hi" {
		t.Errorf("unstamped command = %q, want %q", cmd, "echo hi")
	}
}

func TestSpawnDryRun(t *testing.T) {
	steps := (&procSpawn{}).DryRun(module.Params{"command": "id && whoami"})
	if len(steps) != 1 {
		t.Fatalf("dry run = %v, want 1 line", steps)
	}
	if !strings.Contains(steps[0], "id && whoami") {
		t.Errorf("dry-run line %q should name the command", steps[0])
	}
}
