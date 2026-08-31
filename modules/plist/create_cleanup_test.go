package plistmod

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanup_RemovesEmptyParentDir(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "macnoise_staging")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	fpath := filepath.Join(subdir, "test.plist")
	if err := os.WriteFile(fpath, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &plistCreate{createdPath: fpath}
	if err := p.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		t.Error("plist file should be removed")
	}
	if _, err := os.Stat(subdir); !os.IsNotExist(err) {
		t.Error("empty parent directory should be removed")
	}
}

func TestCleanup_LeavesNonEmptyParentDir(t *testing.T) {
	base := t.TempDir()
	subdir := filepath.Join(base, "macnoise_staging")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	fpath := filepath.Join(subdir, "test.plist")
	other := filepath.Join(subdir, "other.txt")
	if err := os.WriteFile(fpath, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &plistCreate{createdPath: fpath}
	if err := p.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if _, err := os.Stat(subdir); os.IsNotExist(err) {
		t.Error("non-empty parent directory should be preserved")
	}
}
