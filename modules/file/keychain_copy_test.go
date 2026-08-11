package file

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func keychainInfo() module.ModuleInfo {
	return (&fileKeychainCopy{}).Info()
}

// The legacy login.keychain-db is created by a GUI login and is absent on an
// account that has only ever been reached over ssh, where the data-protection
// keychain under a per-user UUID directory is the store that actually holds
// credentials. Enumerating only the documented legacy name would emit nothing
// but indeterminate on such a host.
func TestDefaultKeychainTargetsFindsDataProtectionKeychain(t *testing.T) {
	home := t.TempDir()
	uuidDir := filepath.Join(home, "Library", "Keychains", "C5B97F12-031E-5B0C-82FF-A694DFA73A57")
	if err := os.MkdirAll(uuidDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uuidDir, "keychain-2.db"), []byte("kc"), 0o600); err != nil {
		t.Fatal(err)
	}

	targets := defaultKeychainTargets(home, t.TempDir())

	var found bool
	for _, tg := range targets {
		if tg.kind == "data_protection_keychain" && tg.path == filepath.Join(uuidDir, "keychain-2.db") {
			found = true
		}
	}
	if !found {
		t.Errorf("data-protection keychain under the UUID directory was not enumerated: %+v", targets)
	}
}

// The well-known stores are targeted even when absent, so a host missing any of
// them still emits telemetry rather than silently skipping. This mirrors
// cred_files probing well-known key names that do not exist.
func TestDefaultKeychainTargetsCoversEachKindWhenAbsent(t *testing.T) {
	targets := defaultKeychainTargets(t.TempDir(), t.TempDir())

	kinds := map[string]bool{}
	for _, tg := range targets {
		kinds[tg.kind] = true
	}
	for _, want := range []string{"login_keychain", "system_keychain", "system_data_protection_keychain"} {
		if !kinds[want] {
			t.Errorf("kind %q missing from default targets: %+v", want, targets)
		}
	}
}

// Two keychain directories both contain a keychain-2.db. Without a unique
// destination name the second copy overwrites the first, so the module would
// report two staged keychains while only one file existed.
func TestStagedNamesDisambiguatesCollidingBasenames(t *testing.T) {
	targets := []keychainTarget{
		{kind: "data_protection_keychain", path: "/Users/a/Library/Keychains/UUID-1/keychain-2.db"},
		{kind: "data_protection_keychain", path: "/Users/a/Library/Keychains/UUID-2/keychain-2.db"},
		{kind: "system_keychain", path: "/Library/Keychains/System.keychain"},
	}

	names := stagedNames(targets)
	if len(names) != len(targets) {
		t.Fatalf("got %d names for %d targets", len(names), len(targets))
	}
	seen := map[string]bool{}
	for i, n := range names {
		if seen[n] {
			t.Errorf("destination name %q reused for target %d (%s)", n, i, targets[i].path)
		}
		seen[n] = true
	}
}

// A staged copy of a credential store must not be world-readable. The other
// file modules write 0644, which in a world-writable /tmp would leave the copy
// more exposed than the keychain it came from.
func TestCopyKeychainWritesRestrictiveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has no unix mode bits; this runs in the linux and macOS jobs")
	}
	src := filepath.Join(t.TempDir(), "login.keychain-db")
	if err := os.WriteFile(src, []byte("keychain bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "staged.keychain-db")

	if _, err := copyKeychain(src, dst); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("staged copy mode = %#o, want no group or world access", mode)
	}
}

// The copy must be byte-for-byte. A truncated copy would still produce a
// plausible create event while not being the wholesale copy the module claims.
func TestCopyKeychainCopiesEveryByte(t *testing.T) {
	content := strings.Repeat("keychain payload ", 4096)
	src := filepath.Join(t.TempDir(), "keychain-2.db")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "staged")

	n, err := copyKeychain(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(content)) {
		t.Errorf("copied %d bytes, want %d", n, len(content))
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("staged copy differs from source (%d vs %d bytes)", len(got), len(content))
	}
}

// The copied path: a readable keychain produces both halves of the copy, since
// OCSF has no single activity for one. The read is the credential access and
// the create is the staging, and a consumer needs both.
func TestKeychainEventsEmitsReadAndCopy(t *testing.T) {
	content := "keychain bytes"
	src := filepath.Join(t.TempDir(), "login.keychain-db")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "login_keychain_login.keychain-db")

	evs := keychainEvents(keychainInfo(), keychainTarget{kind: "login_keychain", path: src}, dst)
	if len(evs) != 2 {
		t.Fatalf("got %d events, want a read and a copy: %+v", len(evs), evs)
	}
	if evs[0].EventType != "keychain_read" {
		t.Errorf("first event = %q, want keychain_read", evs[0].EventType)
	}
	if evs[1].EventType != "keychain_copy" {
		t.Errorf("second event = %q, want keychain_copy", evs[1].EventType)
	}
	for _, ev := range evs {
		if got := ev.ResolvedOutcome(); got != module.OutcomeExecuted {
			t.Errorf("%s resolved outcome = %q, want executed", ev.EventType, got)
		}
	}
	if evs[0].Details["bytes_read"] != int64(len(content)) {
		t.Errorf("bytes_read = %v, want %d", evs[0].Details["bytes_read"], len(content))
	}
	if evs[1].Details["staged_path"] != dst {
		t.Errorf("staged_path = %v, want %s", evs[1].Details["staged_path"], dst)
	}
}

// The absent path: a store that does not exist made no access decision, so it
// is indeterminate rather than denied. Reporting it as denied would fabricate a
// refusal the host never issued, the defect PR #28 fixed in the TCC probes.
func TestKeychainEventsAbsentStoreIsIndeterminate(t *testing.T) {
	src := filepath.Join(t.TempDir(), "login.keychain-db") // never created
	dst := filepath.Join(t.TempDir(), "staged")

	evs := keychainEvents(keychainInfo(), keychainTarget{kind: "login_keychain", path: src}, dst)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want only a read: %+v", len(evs), evs)
	}
	if evs[0].Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want indeterminate", evs[0].Outcome)
	}
	if !evs[0].Success {
		t.Error("Success = false; an absent store is a valid observation, not a fault")
	}
	if evs[0].Details["exists"] != false {
		t.Errorf("exists = %v, want false", evs[0].Details["exists"])
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a destination file was created for an absent source")
	}
}

// A failure to write the staged copy is a macnoise fault, not a host refusal.
// Classifying it as a denied read would put a privacy decision in the audit log
// that the host never made.
func TestKeychainEventsStageWriteFailureIsError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "login.keychain-db")
	if err := os.WriteFile(src, []byte("kc"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A destination inside a path component that is a regular file cannot be
	// created on any platform, so this exercises the write failure without
	// needing chmod semantics.
	blocker := filepath.Join(t.TempDir(), "not_a_dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(blocker, "staged")

	evs := keychainEvents(keychainInfo(), keychainTarget{kind: "login_keychain", path: src}, dst)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want a single copy failure: %+v", len(evs), evs)
	}
	if evs[0].EventType != "keychain_copy" {
		t.Errorf("event type = %q, want keychain_copy", evs[0].EventType)
	}
	if got := evs[0].ResolvedOutcome(); got != module.OutcomeError {
		t.Errorf("resolved outcome = %q, want error", got)
	}
}

// The dry run must name the directory that will actually be written, and say
// the copies are staged there, so an operator can see what will be left behind
// before running with --no-cleanup.
func TestKeychainDryRunNamesStageDir(t *testing.T) {
	lines := (&fileKeychainCopy{}).DryRun(module.Params{"stage_dir": "/var/tmp/kc"})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "/var/tmp/kc") {
		t.Errorf("dry run does not mention the stage dir\ngot:\n%s", joined)
	}
	if strings.Contains(joined, defaultKeychainStageDir) {
		t.Errorf("dry run advertises the default stage dir despite an override\ngot:\n%s", joined)
	}
}
