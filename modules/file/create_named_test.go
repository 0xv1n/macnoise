package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileCreate_GenerateNamedFile(t *testing.T) {
	dir := t.TempDir()
	f := &fileCreate{}
	params := module.Params{
		"base_dir": dir,
		"filename": "RECOVER_YOUR_FILES.txt",
		"content":  "MacNoise simulation",
		"count":    "99",
		"prefix":   "ignored_",
	}
	if err := f.Generate(context.Background(), params, noopEmit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	path := filepath.Join(dir, "RECOVER_YOUR_FILES.txt")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read named file: %v", err)
	}
	if got, want := string(content), "MacNoise simulation"; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("created %d files, want 1", len(entries))
	}

	if err := f.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("named file should be removed, stat err = %v", err)
	}
}

func TestFileCreate_RejectsNestedFilename(t *testing.T) {
	f := &fileCreate{}
	err := f.Generate(context.Background(), module.Params{
		"base_dir": t.TempDir(),
		"filename": "nested/RECOVER_YOUR_FILES.txt",
	}, noopEmit)
	if err == nil {
		t.Fatal("Generate succeeded with a nested filename")
	}
}
