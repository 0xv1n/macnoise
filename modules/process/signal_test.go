//go:build darwin

package process

import (
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestSignalDryRun(t *testing.T) {
	steps := (&procSignal{}).DryRun(module.Params{"target_command": "sleep 5"})
	if len(steps) != 2 {
		t.Fatalf("dry run = %v, want 2 lines", steps)
	}
	if !strings.Contains(steps[0], "sleep 5") {
		t.Errorf("first dry-run line %q should name the target command", steps[0])
	}
	if !strings.Contains(steps[1], "SIGSTOP") || !strings.Contains(steps[1], "SIGTERM") {
		t.Errorf("second dry-run line %q should list the signals", steps[1])
	}
}
