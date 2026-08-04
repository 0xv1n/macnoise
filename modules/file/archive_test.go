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
	f := &fileArchive{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"source_dir": sourceDir, "output_path": outputPath, "tool": "zip"}
	if err := f.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
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
		if ev.EventType == "archive_create" && ev.Success {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Error("expected a successful archive_create event")
	}

	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Errorf("expected archive to be removed after Cleanup, stat err = %v", err)
	}
	if _, err := os.Stat(sourceDir); !os.IsNotExist(err) {
		t.Errorf("expected source_dir to be removed after Cleanup, stat err = %v", err)
	}
}
