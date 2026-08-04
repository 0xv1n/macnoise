//go:build integration && darwin

package file

import (
	"context"
	"os"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileCreate_GenerateAndCleanup(t *testing.T) {
	dir := t.TempDir()
	f := &fileCreate{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"base_dir": dir, "count": "3", "prefix": "it_"}
	if err := f.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 files created, found %d", len(entries))
	}

	successCount := 0
	for _, ev := range events {
		if ev.EventType == "file_create" && ev.Success {
			successCount++
		}
	}
	if successCount != 3 {
		t.Errorf("expected 3 successful file_create events, got %d", successCount)
	}

	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir after cleanup: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 files after Cleanup, found %d", len(entries))
	}
}
