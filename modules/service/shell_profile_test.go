//go:build integration && darwin

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestSvcShellProfile_CleanupRestoresOriginalContent(t *testing.T) {
	target := filepath.Join(t.TempDir(), ".zshrc")
	original := "export PATH=/usr/local/bin:$PATH\nalias ll='ls -la'\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	s := &svcShellProfile{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"target": target, "payload": "export MACNOISE_PERSIST=1"}
	if err := s.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	modified, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after Generate: %v", err)
	}
	if !strings.Contains(string(modified), "export MACNOISE_PERSIST=1") {
		t.Error("payload not written to profile")
	}
	if !strings.HasPrefix(string(modified), original) {
		t.Error("Generate must append, not overwrite existing profile content")
	}

	if len(events) != 1 || events[0].EventType != "shell_profile_modify" || !events[0].Success {
		t.Errorf("expected one successful shell_profile_modify event, got %+v", events)
	}

	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after Cleanup: %v", err)
	}
	if string(restored) != original {
		t.Errorf("Cleanup did not restore original content\n got: %q\nwant: %q", restored, original)
	}
}

// Cleanup walks the file removing every marker block, so a profile that
// accumulated blocks across repeated runs must come back fully clean.
func TestSvcShellProfile_CleanupRemovesRepeatedBlocks(t *testing.T) {
	target := filepath.Join(t.TempDir(), ".zshrc")
	original := "# user config\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	emit := func(module.TelemetryEvent) {}
	params := module.Params{"target": target, "payload": "export MACNOISE_PERSIST=1"}

	s := &svcShellProfile{}
	for i := 0; i < 3; i++ {
		if err := s.Generate(context.Background(), params, emit); err != nil {
			t.Fatalf("Generate run %d: %v", i, err)
		}
	}

	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after Cleanup: %v", err)
	}
	if string(restored) != original {
		t.Errorf("Cleanup left residue after 3 appends\n got: %q\nwant: %q", restored, original)
	}
	if strings.Contains(string(restored), shellProfileMarkerStart) {
		t.Error("marker still present after Cleanup")
	}
}
