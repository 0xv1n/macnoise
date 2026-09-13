package file

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileArchiveCleanupRefusesLaterChangesAndPreservesSource(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar is required")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	writeTestFile(t, source, "source")
	archive := filepath.Join(dir, "archive.tar.gz")
	f := &fileArchive{}
	ctx, _ := outputContext()
	if err := f.Generate(ctx, module.Params{"source_path": source, "output_path": archive, "tool": "tar"}, noopEmit); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("later archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Cleanup(context.Background()); err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Cleanup = %v, want conflict", err)
	}
	if data, err := os.ReadFile(archive); err != nil || string(data) != "later archive" {
		t.Fatalf("later archive change was not preserved: data=%q err=%v", data, err)
	}
	if data, err := os.ReadFile(source); err != nil || string(data) != "source" {
		t.Fatalf("archive source changed: data=%q err=%v", data, err)
	}
}

func TestFileArchiveRejectsOutputInsideSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	err := (&fileArchive{}).ValidateParams(module.Params{
		"source_path": source,
		"output_path": filepath.Join(source, "archive.zip"),
	})
	if err == nil {
		t.Fatal("archive accepted an output path inside its source")
	}
}
