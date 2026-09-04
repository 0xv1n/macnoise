package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestGatekeeperDryRun(t *testing.T) {
	steps := (&procGatekeeper{}).DryRun(module.Params{"target_path": "/tmp/gk_test"})
	if len(steps) != 4 {
		t.Fatalf("dry run = %v, want 4 steps", steps)
	}
	joined := strings.Join(steps, "\n")
	for _, want := range []string{"com.apple.quarantine", "spctl --status", "/tmp/gk_test"} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run missing %q:\n%s", want, joined)
		}
	}
}

func TestGatekeeperCleanup_RemovesTargetFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gk_target")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &procGatekeeper{targetPath: path}
	if err := p.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should be removed, stat err = %v", err)
	}
}

func TestGatekeeperCleanup_ToleratesMissingAndEmpty(t *testing.T) {
	// No target path recorded (Generate never ran).
	if err := (&procGatekeeper{}).Cleanup(); err != nil {
		t.Errorf("Cleanup with no target should be a no-op, got %v", err)
	}
	// Target recorded but already gone.
	p := &procGatekeeper{targetPath: filepath.Join(t.TempDir(), "never_created")}
	if err := p.Cleanup(); err != nil {
		t.Errorf("Cleanup of an absent file should tolerate IsNotExist, got %v", err)
	}
}
