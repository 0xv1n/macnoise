//go:build integration && darwin

package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

// This module has no parameter for the agent directory - it always writes to
// the real ~/Library/LaunchAgents - so the test uses a distinctive label and
// registers its own removal, rather than relying on Cleanup() alone (which is
// the thing under test and may itself be broken).
func TestSvcLaunchAgent_GenerateAndCleanup(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	const label = "com.macnoise.integrationtest.agent"
	plistPath := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	t.Cleanup(func() { _ = os.Remove(plistPath) })

	s := &svcLaunchAgent{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

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
		if ev.EventType == "launchagent_create" && ev.Success {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Error("expected a successful launchagent_create event")
	}

	// launchctl bootstrap is deliberately not asserted: it needs a GUI (Aqua)
	// session, which a CI runner has no guarantee of, and the module already
	// treats a bootstrap failure as valid telemetry rather than an error.

	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Errorf("expected plist to be removed after Cleanup, stat err = %v", err)
	}
}
