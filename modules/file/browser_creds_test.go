//go:build integration && darwin

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// writeCredFixture creates path and its parents with the given contents.
func writeCredFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func eventsByPath(events []module.TelemetryEvent) map[string]module.TelemetryEvent {
	byPath := map[string]module.TelemetryEvent{}
	for _, ev := range events {
		if p, ok := ev.Details["path"].(string); ok {
			byPath[p] = ev
		}
	}
	return byPath
}

// The module reads $HOME-relative paths, and os.UserHomeDir resolves $HOME on
// darwin, so pointing HOME at a fixture tree exercises the real read path
// without touching the running user's actual browser data.
func TestBrowserCreds_ReadsRealFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	loginData := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data")
	writeCredFixture(t, loginData, "fake chrome login db payload")

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "chrome"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ev, ok := eventsByPath(events)[loginData]
	if !ok {
		t.Fatalf("no event emitted for %s", loginData)
	}
	if ev.EventType != "browser_cred_read" {
		t.Errorf("EventType = %q, want browser_cred_read", ev.EventType)
	}
	if got := ev.Details["bytes_read"]; got != int64(len("fake chrome login db payload")) {
		t.Errorf("bytes_read = %v, want %d", got, len("fake chrome login db payload"))
	}
	if ev.Details["accessible"] != true {
		t.Errorf("accessible = %v, want true", ev.Details["accessible"])
	}
}

func TestBrowserCreds_MissingPathIsProbeNotRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "chrome"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected probe events for absent chrome paths")
	}
	for _, ev := range events {
		if ev.EventType != "browser_cred_probe" {
			t.Errorf("EventType = %q, want browser_cred_probe for absent path %v", ev.EventType, ev.Details["path"])
		}
		if ev.Details["exists"] != false {
			t.Errorf("exists = %v, want false", ev.Details["exists"])
		}
	}
}

// An unreadable file must be reported as an attempted read, since a TCC or
// POSIX refusal is the signal detections key on - not skipped as if absent.
func TestBrowserCreds_UnreadableFileIsDeniedRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, mode bits do not deny access")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	cookies := filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies")
	writeCredFixture(t, cookies, "fake safari cookies")
	if err := os.Chmod(cookies, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "safari"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ev, ok := eventsByPath(events)[cookies]
	if !ok {
		t.Fatalf("no event emitted for %s", cookies)
	}
	if ev.EventType != "browser_cred_read" {
		t.Errorf("EventType = %q, want browser_cred_read", ev.EventType)
	}
	if ev.Details["accessible"] != false {
		t.Errorf("accessible = %v, want false", ev.Details["accessible"])
	}
	if ev.Error == "" {
		t.Error("expected the denial reason to be recorded in Error")
	}
	if !ev.Success {
		t.Error("Success = false, want true: a denied read is expected telemetry, not a module failure")
	}
}

// The AMOS scenario claims Firefox coverage of logins.json and key4.db, which
// requires enumerating the randomly-named profile directories.
func TestBrowserCreds_EnumeratesFirefoxProfiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	profile := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles", "abc123.default-release")
	logins := filepath.Join(profile, "logins.json")
	key4 := filepath.Join(profile, "key4.db")
	writeCredFixture(t, logins, `{"logins":[]}`)
	writeCredFixture(t, key4, "fake key4 db")

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "firefox"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	byPath := eventsByPath(events)
	for _, want := range []string{logins, key4} {
		ev, ok := byPath[want]
		if !ok {
			t.Errorf("no event emitted for %s", want)
			continue
		}
		if ev.EventType != "browser_cred_read" {
			t.Errorf("%s: EventType = %q, want browser_cred_read", want, ev.EventType)
		}
	}
}

// With Firefox absent the profiles directory itself must still produce a probe,
// so a missing browser is visible in telemetry rather than silently skipped.
func TestBrowserCreds_AbsentFirefoxStillProbes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "firefox"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 probe event for absent firefox, got %d", len(events))
	}
	if events[0].EventType != "browser_cred_probe" {
		t.Errorf("EventType = %q, want browser_cred_probe", events[0].EventType)
	}
}

// A directory sitting where a credential file is expected must not be reported
// as a denied read: nothing was there to read in the first place.
func TestBrowserCreds_DirectoryTargetIsProbe(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	loginData := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Login Data")
	if err := os.MkdirAll(loginData, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	f := &fileBrowserCreds{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := f.Generate(context.Background(), module.Params{"browsers": "chrome"}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ev, ok := eventsByPath(events)[loginData]
	if !ok {
		t.Fatalf("no event emitted for %s", loginData)
	}
	if ev.EventType != "browser_cred_probe" {
		t.Errorf("EventType = %q, want browser_cred_probe for a directory", ev.EventType)
	}
}
