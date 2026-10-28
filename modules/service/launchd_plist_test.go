package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateLaunchdPlistRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.plist")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := createLaunchdPlist(path, "com.macnoise.test", "/usr/bin/true"); err == nil {
		t.Fatal("createLaunchdPlist replaced an existing file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatalf("existing plist changed: data=%q err=%v", data, err)
	}
}

func TestLaunchdPlistCleanupRefusesChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.plist")
	owned, err := createLaunchdPlist(path, "com.macnoise.test", "/usr/bin/true")
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
		t.Fatalf("changed plist was not preserved: data=%q err=%v", data, err)
	}
}
