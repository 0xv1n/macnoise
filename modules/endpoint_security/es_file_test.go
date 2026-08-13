//go:build integration && darwin

package endpointsecurity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestESFile_GenerateEmitsFullFileEventCycle(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "es")
	e := &esFile{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := e.Generate(context.Background(), module.Params{"work_dir": workDir}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer e.Cleanup() //nolint:errcheck

	// Order is load-bearing, not incidental: setmode and rename have to happen
	// while the file still exists, and rename has to precede the unlink that
	// removes it under its new name.
	want := []string{
		"es_notify_create",
		"es_notify_open",
		"es_notify_write",
		"es_notify_setmode",
		"es_notify_rename",
		"es_notify_unlink",
	}
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

	// Neither name may survive Generate. Asserting only the original would pass
	// even if the rename left the file behind under its new name.
	for _, name := range []string{"es_notify_create.txt", "es_notify_rename.txt"} {
		p := filepath.Join(workDir, name)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be gone after Generate, stat err = %v", p, err)
		}
	}
}

// Cleanup must remove whatever path is currently tracked, including the renamed
// one, so a later change that hardcodes the original filename is caught.
//
// This does NOT cover Generate's side of that bookkeeping. Generate only leaves
// createdPath pointing at the renamed file when the rename succeeds and the
// unlink then fails, and there is no way to force that ordering from a test
// without adding a seam purely for testing. Deleting the assignment in Generate
// leaves every test green, which is worth knowing rather than assuming the line
// is covered.
func TestESFile_CleanupRemovesTrackedRenamedPath(t *testing.T) {
	workDir := t.TempDir()
	renamed := filepath.Join(workDir, "es_notify_rename.txt")

	e := &esFile{createdPath: renamed}
	if err := os.WriteFile(renamed, []byte("es"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := e.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(renamed); !os.IsNotExist(err) {
		t.Errorf("renamed file survived cleanup at %s", renamed)
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
