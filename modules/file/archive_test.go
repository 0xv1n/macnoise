//go:build integration && darwin

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileArchive_GenerateAndCleanup(t *testing.T) {
	dir := t.TempDir()
	sourceDir := filepath.Join(dir, "src")
	outputPath := filepath.Join(dir, "out.zip")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "existing.txt"), []byte("existing source"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fileArchive{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) error { events = append(events, ev); return nil }

	params := module.Params{"source_path": sourceDir, "output_path": outputPath, "tool": "zip"}
	ctx, outputs := outputContext()
	if err := f.Generate(ctx, params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if outputs["path"] != outputPath {
		t.Fatalf("path output = %v, want %s", outputs["path"], outputPath)
	}

	fi, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("archive not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("archive file is empty")
	}

	var sawSuccess bool
	for _, ev := range events {
		if ev.EventType == "archive_create" && ev.Outcome == module.OutcomeExecuted {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Error("expected a successful archive_create event")
	}

	if err := f.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Errorf("expected archive to be removed after Cleanup, stat err = %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(sourceDir, "existing.txt")); err != nil || string(data) != "existing source" {
		t.Errorf("archive source changed during cleanup: data=%q err=%v", data, err)
	}
}
