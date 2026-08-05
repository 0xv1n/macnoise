//go:build integration && darwin

package endpointsecurity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestESFile_GenerateEmitsFullCreateWriteUnlinkCycle(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	e := &esFile{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := e.Generate(context.Background(), module.Params{"work_dir": workDir}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer e.Cleanup() //nolint:errcheck

	want := []string{"es_notify_create", "es_notify_write", "es_notify_unlink"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i, evType := range want {
		if events[i].EventType != evType {
			t.Errorf("event[%d] = %q, want %q", i, events[i].EventType, evType)
		}
		if !events[i].Success {
			t.Errorf("event %q did not succeed: %s", evType, events[i].Error)
		}
	}

	// The unlink step deletes the file as part of the telemetry cycle, so
	// nothing should survive Generate even before Cleanup runs.
	target := filepath.Join(workDir, "es_notify_create.txt")
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected %s to be unlinked by Generate, stat err = %v", target, err)
	}
}

func TestESFile_CleanupAfterSuccessfulUnlinkIsNoOp(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	e := &esFile{}
	emit := func(module.TelemetryEvent) {}

	if err := e.Generate(context.Background(), module.Params{"work_dir": workDir}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := e.Cleanup(); err != nil {
		t.Errorf("Cleanup after a successful unlink must not error, got %v", err)
	}
}
