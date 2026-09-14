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
	emit := captureServiceEvents(&events)

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

	if len(events) != 1 || events[0].EventType != "shell_profile_modify" || events[0].Outcome != module.OutcomeExecuted {
		t.Errorf("expected one successful shell_profile_modify event, got %+v", events)
	}

	if err := s.Cleanup(context.Background()); err != nil {
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

func TestSvcShellProfile_CleanupOwnsOnlyItsBlock(t *testing.T) {
	target := filepath.Join(t.TempDir(), ".zshrc")
	original := "# user config\n"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	first := &svcShellProfile{}
	second := &svcShellProfile{}
	params := module.Params{"target": target, "payload": "export MACNOISE_PERSIST=1"}
	if err := first.Generate(module.ContextWithRunID(context.Background(), "first"), params, discardServiceEvent); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	if err := second.Generate(module.ContextWithRunID(context.Background(), "second"), params, discardServiceEvent); err != nil {
		t.Fatalf("second Generate: %v", err)
	}

	if err := first.Cleanup(context.Background()); err != nil {
		t.Fatalf("first Cleanup: %v", err)
	}
	remaining, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after first Cleanup: %v", err)
	}
	if strings.Contains(string(remaining), "mn:first") {
		t.Error("first invocation marker remains after its cleanup")
	}
	if !strings.Contains(string(remaining), "mn:second") {
		t.Error("first cleanup removed the second invocation's marker")
	}

	if err := second.Cleanup(context.Background()); err != nil {
		t.Fatalf("second Cleanup: %v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after second Cleanup: %v", err)
	}
	if string(restored) != original {
		t.Errorf("final content = %q, want %q", restored, original)
	}
}
