package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileReadPublishesOnlySuccessfulLiteralPaths(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "literal.txt")
	writeTestFile(t, existing, "payload")
	missing := filepath.Join(t.TempDir(), "missing.txt")
	ctx, outputs := outputContext()
	var events []module.TelemetryEvent
	if err := (&fileRead{}).Generate(ctx, module.Params{"paths": []string{existing, missing}}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	paths, ok := outputs["paths"].([]string)
	if !ok || len(paths) != 1 || paths[0] != existing {
		t.Fatalf("paths = %#v, want only %s", outputs["paths"], existing)
	}
	if len(events) != 2 || events[0].Outcome != module.OutcomeExecuted || events[1].Outcome != module.OutcomeIndeterminate {
		t.Fatalf("events = %+v", events)
	}
}

func TestFileCopyCleanupRefusesLaterChanges(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.txt")
	writeTestFile(t, source, "original")
	destinationDir := filepath.Join(t.TempDir(), "stage")
	ctx, outputs := outputContext()
	f := &fileCopy{}
	if err := f.Generate(ctx, module.Params{"source_paths": []string{source}, "destination_dir": destinationDir}, noopEmit); err != nil {
		t.Fatal(err)
	}
	copied := outputs["paths"].([]string)[0]
	if err := os.WriteFile(copied, []byte("later change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Cleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Cleanup = %v, want conflict", err)
	}
	if data, err := os.ReadFile(copied); err != nil || string(data) != "later change" {
		t.Fatalf("later change was not preserved: data=%q err=%v", data, err)
	}
}

func TestFileCopyNeverOverwritesDestination(t *testing.T) {
	source := filepath.Join(t.TempDir(), "same.txt")
	writeTestFile(t, source, "source")
	destinationDir := t.TempDir()
	destination := filepath.Join(destinationDir, "same.txt")
	writeTestFile(t, destination, "preexisting")
	ctx, _ := outputContext()
	f := &fileCopy{}
	if err := f.Generate(ctx, module.Params{"source_paths": []string{source}, "destination_dir": destinationDir}, noopEmit); err == nil {
		t.Fatal("Generate overwrote an existing destination")
	}
	if err := f.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "preexisting" {
		t.Fatalf("destination changed: data=%q err=%v", data, err)
	}
}
