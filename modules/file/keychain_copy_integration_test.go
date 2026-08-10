//go:build integration && darwin

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A chmod-000 keychain exists but cannot be opened. That refusal is the
// detection signal and must read as denied, not as an absent store and not as a
// macnoise failure. The same distinction cred_files draws, and the reason this
// module opens rather than stats.
func TestKeychainCopy_UnreadableKeychainIsDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, mode bits do not deny access")
	}

	src := filepath.Join(t.TempDir(), "login.keychain-db")
	if err := os.WriteFile(src, []byte("keychain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(src, 0o600) })

	dst := filepath.Join(t.TempDir(), "staged")
	evs := keychainEvents(keychainInfo(), keychainTarget{kind: "login_keychain", path: src}, dst)

	if len(evs) != 1 {
		t.Fatalf("got %d events, want only a denied read: %+v", len(evs), evs)
	}
	if evs[0].Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want denied", evs[0].Outcome)
	}
	if !evs[0].Success {
		t.Error("Success = false: a permission denial is expected telemetry, not a macnoise fault")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a staged copy was created from a keychain that could not be read")
	}
}

// End to end against a temp HOME with a planted login keychain, plus the real
// /Library/Keychains this host has. The staged copy must be byte-for-byte and
// not world-readable, and no target may report a macnoise fault.
func TestKeychainCopy_GenerateStagesRealCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	keychainDir := filepath.Join(home, "Library", "Keychains")
	if err := os.MkdirAll(keychainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("kych\x00binary keychain bytes\x00")
	loginKeychain := filepath.Join(keychainDir, "login.keychain-db")
	if err := os.WriteFile(loginKeychain, content, 0o600); err != nil {
		t.Fatal(err)
	}

	stageDir := filepath.Join(t.TempDir(), "stage")
	mod := &fileKeychainCopy{}

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := mod.Generate(context.Background(), module.Params{"stage_dir": stageDir}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var staged string
	for _, ev := range events {
		if ev.Outcome == module.OutcomeError {
			t.Errorf("%s reported a macnoise failure: %s", ev.EventType, ev.Error)
		}
		if kind, _ := ev.Details["kind"].(string); kind == "login_keychain" && ev.EventType == "keychain_copy" {
			staged, _ = ev.Details["staged_path"].(string)
		}
	}
	if staged == "" {
		t.Fatalf("no copy event for the planted login keychain: %+v", events)
	}

	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("staged copy is not readable: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("staged copy differs from the source keychain")
	}
	fi, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("staged keychain copy mode = %#o, want no group or world access", mode)
	}

	// The system keychain is world-readable on a stock macOS install, so a real
	// host must produce a copy of it too. This is the half a temp HOME cannot
	// fake, and it is what proves the enumeration points at real paths.
	var sawSystem bool
	for _, ev := range events {
		if kind, _ := ev.Details["kind"].(string); kind == "system_keychain" && ev.EventType == "keychain_copy" {
			sawSystem = true
		}
	}
	if !sawSystem {
		t.Error("no copy event for /Library/Keychains/System.keychain")
	}
}

// Cleanup must remove the staged copies. A run that leaves duplicates of real
// credential stores behind is the failure mode that actually matters here, and
// it is silent without this assertion.
func TestKeychainCopy_CleanupRemovesStagedCopies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	keychainDir := filepath.Join(home, "Library", "Keychains")
	if err := os.MkdirAll(keychainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keychainDir, "login.keychain-db"), []byte("kc"), 0o600); err != nil {
		t.Fatal(err)
	}

	stageDir := filepath.Join(t.TempDir(), "stage")
	mod := &fileKeychainCopy{}
	if err := mod.Generate(context.Background(), module.Params{"stage_dir": stageDir}, func(module.TelemetryEvent) {}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	entries, err := os.ReadDir(stageDir)
	if err != nil {
		t.Fatalf("stage dir not created: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("nothing was staged, so cleanup would pass vacuously")
	}

	if err := mod.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Errorf("staged keychain copies survived cleanup at %s", stageDir)
	}
}
