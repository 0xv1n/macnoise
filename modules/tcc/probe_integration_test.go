//go:build integration && darwin

package tcc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runProbe(t *testing.T, gen module.Generator, params module.Params) module.TelemetryEvent {
	t.Helper()
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := gen.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

func TestTCCFDA_GrantedOnReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "TCC.db")
	if err := os.WriteFile(path, []byte("fake tcc db"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ev := runProbe(t, &tccFDA{}, module.Params{"tcc_path": path})
	if ev.Details["result"] != "granted" {
		t.Errorf("result = %v, want granted", ev.Details["result"])
	}
	if ev.Details["file_size"] != int64(len("fake tcc db")) {
		t.Errorf("file_size = %v, want %d", ev.Details["file_size"], len("fake tcc db"))
	}
}

// The regression that motivated this change: a path that was never created
// cannot have been denied by TCC, and reporting it as a denial fabricates a
// privacy decision for anything downstream that counts denials as signal.
func TestTCCFDA_MissingPathIsAbsentNotDenied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does_not_exist", "TCC.db")

	ev := runProbe(t, &tccFDA{}, module.Params{"tcc_path": path})
	if ev.Details["result"] != "absent" {
		t.Errorf("result = %v, want absent", ev.Details["result"])
	}
	if !ev.Success {
		t.Error("Success = false, want true: an absent target is a valid observation")
	}
	if ev.Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeIndeterminate)
	}
}

func TestTCCFDA_UnreadableFileIsDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, mode bits do not deny access")
	}

	path := filepath.Join(t.TempDir(), "TCC.db")
	if err := os.WriteFile(path, []byte("fake tcc db"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	ev := runProbe(t, &tccFDA{}, module.Params{"tcc_path": path})
	if ev.Details["result"] != "denied" {
		t.Errorf("result = %v, want denied", ev.Details["result"])
	}
	if ev.Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeDenied)
	}
	if !ev.Success {
		t.Error("Success = false: a TCC denial is expected telemetry, not a macnoise failure")
	}
}

// The default target must be the per-user TCC database. The system one under
// /Library is root-owned, so an unprivileged run is refused by POSIX before
// TCC is consulted, making a denial there unattributable to Full Disk Access.
func TestTCCFDA_DefaultTargetsPerUserDatabase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	actions := (&tccFDA{}).DryRun(module.Params{})
	if len(actions) != 1 {
		t.Fatalf("expected 1 dry-run action, got %d", len(actions))
	}
	want := filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db")
	if !strings.Contains(actions[0], want) {
		t.Errorf("dry-run action %q does not target the per-user TCC.db at %q", actions[0], want)
	}
}

func TestTCCContacts_GrantedOnReadableDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ab := filepath.Join(home, "Library", "Application Support", "AddressBook")
	if err := os.MkdirAll(ab, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ab, "AddressBook-v22.abcddb"), []byte("db"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ev := runProbe(t, &tccContacts{}, module.Params{})
	if ev.Details["result"] != "granted" {
		t.Errorf("result = %v, want granted", ev.Details["result"])
	}
	if ev.Details["entry_count"] != 1 {
		t.Errorf("entry_count = %v, want 1", ev.Details["entry_count"])
	}
}

// A machine that has never used Contacts has no AddressBook directory. That is
// an absent resource, not a TCC refusal.
func TestTCCContacts_NoAddressBookIsAbsentNotDenied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ev := runProbe(t, &tccContacts{}, module.Params{})
	if ev.Details["result"] != "absent" {
		t.Errorf("result = %v, want absent", ev.Details["result"])
	}
	if !ev.Success {
		t.Error("Success = false, want true: an absent target is a valid observation")
	}
	if ev.Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeIndeterminate)
	}
}

func TestTCCContacts_UnreadableDirIsDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, mode bits do not deny access")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	ab := filepath.Join(home, "Library", "Application Support", "AddressBook")
	if err := os.MkdirAll(ab, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(ab, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ab, 0o755) })

	ev := runProbe(t, &tccContacts{}, module.Params{})
	if ev.Details["result"] != "denied" {
		t.Errorf("result = %v, want denied", ev.Details["result"])
	}
	if ev.Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeDenied)
	}
}
