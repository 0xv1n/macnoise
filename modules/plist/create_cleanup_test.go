package plistmod

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func discardPlistCreateEvent(module.TelemetryEvent) error { return nil }

func TestPlistCreateRefusesExistingOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.plist")
	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := (&plistCreate{}).Generate(context.Background(), module.Params{"output_path": path}, discardPlistCreateEvent)
	if err == nil {
		t.Fatal("Generate overwrote an existing output")
	}
	if data, readErr := os.ReadFile(path); readErr != nil || string(data) != "keep" {
		t.Fatalf("existing output changed: data=%q err=%v", data, readErr)
	}
}

func TestPlistCreateCleanupRefusesChangedOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created.plist")
	p := &plistCreate{}
	if err := p.Generate(context.Background(), module.Params{"output_path": path}, discardPlistCreateEvent); err != nil {
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
		t.Fatalf("changed output was not preserved: data=%q err=%v", data, readErr)
	}
}

func TestPlistCreateCleanupRemovesCreatedParentDir(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "macnoise_staging")
	fpath := filepath.Join(subdir, "test.plist")
	p := &plistCreate{}
	if err := p.Generate(context.Background(), module.Params{"output_path": fpath}, discardPlistCreateEvent); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		t.Error("plist file should be removed")
	}
	if _, err := os.Stat(subdir); !os.IsNotExist(err) {
		t.Error("empty parent directory should be removed")
	}
}

func TestPlistCreateCleanupPreservesPreexistingParentDir(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "macnoise_staging")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	fpath := filepath.Join(subdir, "test.plist")
	p := &plistCreate{}
	if err := p.Generate(context.Background(), module.Params{"output_path": fpath}, discardPlistCreateEvent); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(subdir); os.IsNotExist(err) {
		t.Error("pre-existing parent directory should be preserved")
	}
}
