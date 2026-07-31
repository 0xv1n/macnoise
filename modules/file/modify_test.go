package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func noopEmit(module.TelemetryEvent) {}

// Cleanup must delete a file that fileModify itself created, not leave an
// empty file behind. The bug: origContent was set to a non-nil empty slice
// when the target didn't exist, so Cleanup's `origContent == nil` check
// never took the os.Remove branch.
func TestFileModify_CleanupRemovesFileItCreated(t *testing.T) {
	target := filepath.Join(t.TempDir(), "does-not-exist-yet.txt")

	f := &fileModify{}
	params := module.Params{"target_path": target}
	if err := f.Generate(context.Background(), params, noopEmit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected Generate to create %s: %v", target, err)
	}

	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected %s to be removed by Cleanup, stat err = %v", target, err)
	}
}

// Cleanup must restore a pre-existing file's exact original content, not
// leave macnoise's appended modification in place.
func TestFileModify_CleanupRestoresPriorContent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "existing.txt")
	original := []byte("original content\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f := &fileModify{}
	params := module.Params{"target_path": target}
	if err := f.Generate(context.Background(), params, noopEmit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	modified, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after Generate: %v", err)
	}
	if string(modified) == string(original) {
		t.Fatal("Generate did not modify the file, test setup is invalid")
	}

	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after Cleanup: %v", err)
	}
	if string(restored) != string(original) {
		t.Errorf("Cleanup did not restore original content:\n got:  %q\n want: %q", restored, original)
	}
}
