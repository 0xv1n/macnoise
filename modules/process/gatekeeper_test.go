package process

import (
	"context"
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

func TestGatekeeperGenerateRefusesExistingTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := (&procGatekeeper{}).Generate(context.Background(), module.Params{"target_path": path}, func(module.TelemetryEvent) error { return nil })
	if err == nil {
		t.Fatal("Generate overwrote an existing target")
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "keep" {
		t.Fatalf("existing target changed: data=%q err=%v", data, readErr)
	}
}

func TestGatekeeperCleanupRefusesChangedTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target")
	p := &procGatekeeper{}
	if err := p.Generate(context.Background(), module.Params{"target_path": path}, func(module.TelemetryEvent) error { return nil }); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := p.Cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Cleanup = %v, want conflict", err)
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "changed" {
		t.Fatalf("changed target was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestGatekeeperCleanup_RemovesTargetFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gk_target")
	p := &procGatekeeper{}
	if err := p.Generate(context.Background(), module.Params{"target_path": path}, func(module.TelemetryEvent) error { return nil }); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("target file should be removed, stat err = %v", err)
	}
}

func TestGatekeeperCleanup_ToleratesMissingAndEmpty(t *testing.T) {
	if err := (&procGatekeeper{}).Cleanup(context.Background()); err != nil {
		t.Errorf("Cleanup with no target should be a no-op, got %v", err)
	}
	path := filepath.Join(t.TempDir(), "removed")
	p := &procGatekeeper{}
	if err := p.Generate(context.Background(), module.Params{"target_path": path}, func(module.TelemetryEvent) error { return nil }); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Errorf("Cleanup of an absent file should tolerate IsNotExist, got %v", err)
	}
}
