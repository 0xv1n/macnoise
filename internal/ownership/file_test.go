package ownership

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFileRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := CreateFile(path, []byte("replace"), 0o600); err == nil {
		t.Fatal("CreateFile replaced an existing file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatalf("existing file changed: data=%q err=%v", data, err)
	}
}

func TestFileRemoveRefusesChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	owned, err := CreateFile(path, []byte("created"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := owned.Remove(); err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Remove = %v, want conflict", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "changed" {
		t.Fatalf("changed file was not preserved: data=%q err=%v", data, err)
	}
}

func TestFileRemoveRefusesSymlinkReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned")
	movedPath := filepath.Join(dir, "moved")
	owned, err := CreateFile(path, []byte("created"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(movedPath, path); err != nil {
		t.Fatal(err)
	}

	if err := owned.Remove(); err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("Remove = %v, want conflict", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement symlink was not preserved: info=%v err=%v", info, err)
	}
}

func TestRemoveDirectoriesRemovesOnlyCreatedDirectories(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "created", "nested")
	dirs, err := EnsureDirectories(child, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveDirectories(dirs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("created directory survived: %v", err)
	}
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("existing parent was removed: %v", err)
	}
}

func TestRemoveDirectoriesRefusesSymlinkReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned")
	movedPath := filepath.Join(dir, "moved")
	dirs, err := EnsureDirectories(path, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(movedPath, path); err != nil {
		t.Fatal(err)
	}

	if err := RemoveDirectories(dirs); err == nil || !strings.Contains(err.Error(), "cleanup conflict") {
		t.Fatalf("RemoveDirectories = %v, want conflict", err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement symlink was not preserved: info=%v err=%v", info, err)
	}
}
