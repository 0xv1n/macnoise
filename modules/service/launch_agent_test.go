//go:build integration && darwin

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

func TestSvcLaunchAgentRefusesExistingPlist(t *testing.T) {
	target, err := resolveLaunchdUser()
	if err != nil {
		t.Fatalf("resolveLaunchdUser: %v", err)
	}
	label := fmt.Sprintf("com.macnoise.integrationtest.existing.%d", os.Getpid())
	plistPath := filepath.Join(target.home, "Library", "LaunchAgents", label+".plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &svcLaunchAgent{}
	t.Cleanup(func() {
		_ = s.Cleanup(context.Background())
		_ = os.Remove(plistPath)
	})
	err = s.Generate(context.Background(), module.Params{"label": label, "program": "/usr/bin/true"}, discardServiceEvent)
	if err == nil {
		t.Fatal("Generate overwrote an existing LaunchAgent plist")
	}
	if data, readErr := os.ReadFile(plistPath); readErr != nil || string(data) != "keep" {
		t.Fatalf("existing plist changed: data=%q err=%v", data, readErr)
	}
}

// This module has no parameter for the agent directory - it always writes to
// the real ~/Library/LaunchAgents - so the test uses a distinctive label and
// registers its own removal, rather than relying on Cleanup() alone (which is
// the thing under test and may itself be broken).
func TestSvcLaunchAgent_GenerateAndCleanup(t *testing.T) {
	target, err := resolveLaunchdUser()
	if err != nil {
		t.Fatalf("resolveLaunchdUser: %v", err)
	}
	const label = "com.macnoise.integrationtest.agent"
	plistPath := filepath.Join(target.home, "Library", "LaunchAgents", label+".plist")
	t.Cleanup(func() { _ = os.Remove(plistPath) })

	s := &svcLaunchAgent{}
	var events []module.TelemetryEvent
	emit := captureServiceEvents(&events)

	params := module.Params{"label": label, "program": "/usr/bin/true"}
	if err := s.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	f, err := os.Open(plistPath)
	if err != nil {
		t.Fatalf("LaunchAgent plist not created: %v", err)
	}
	var decoded map[string]any
	decodeErr := plist.NewDecoder(f).Decode(&decoded)
	_ = f.Close()
	if decodeErr != nil {
		t.Fatalf("created file is not a valid plist: %v", decodeErr)
	}
	if decoded["Label"] != label {
		t.Errorf("Label = %v, want %v", decoded["Label"], label)
	}

	var sawCreate bool
	for _, ev := range events {
		if ev.EventType == "launchagent_create" && ev.Outcome == module.OutcomeExecuted {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Error("expected a successful launchagent_create event")
	}

	// launchctl bootstrap is deliberately not asserted: it needs a GUI (Aqua)
	// session, which a CI runner has no guarantee of, and the module already
	// treats a bootstrap failure as valid telemetry rather than an error.

	if err := s.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Errorf("expected plist to be removed after Cleanup, stat err = %v", err)
	}
}
