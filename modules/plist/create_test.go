//go:build integration && darwin

package plistmod

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

func TestPlistCreate_GenerateAndCleanup(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "test.plist")
	p := &plistCreate{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"output_path": outPath, "bundle_id": "com.macnoise.integrationtest"}
	if err := p.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("plist not created: %v", err)
	}
	defer f.Close()
	var decoded map[string]any
	if err := plist.NewDecoder(f).Decode(&decoded); err != nil {
		t.Fatalf("created file is not a valid plist: %v", err)
	}
	if decoded["CFBundleIdentifier"] != "com.macnoise.integrationtest" {
		t.Errorf("CFBundleIdentifier = %v, want com.macnoise.integrationtest", decoded["CFBundleIdentifier"])
	}

	var sawSuccess bool
	for _, ev := range events {
		if ev.EventType == "plist_create" && ev.Success {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Error("expected a successful plist_create event")
	}

	if err := p.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("expected plist to be removed after Cleanup, stat err = %v", err)
	}
}

func TestPlistCreate_LaunchAgentMode(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "agent.plist")
	p := &plistCreate{}
	emit := func(module.TelemetryEvent) {}

	params := module.Params{
		"output_path": outPath,
		"mode":        "launchagent",
		"label":       "com.macnoise.integrationtest.agent",
		"program":     "/usr/bin/true",
	}
	if err := p.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer p.Cleanup() //nolint:errcheck

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("plist not created: %v", err)
	}
	defer f.Close()
	var decoded map[string]any
	if err := plist.NewDecoder(f).Decode(&decoded); err != nil {
		t.Fatalf("created file is not a valid plist: %v", err)
	}
	if decoded["Label"] != "com.macnoise.integrationtest.agent" {
		t.Errorf("Label = %v, want com.macnoise.integrationtest.agent", decoded["Label"])
	}
	if decoded["RunAtLoad"] != true {
		t.Errorf("RunAtLoad = %v, want true", decoded["RunAtLoad"])
	}
}
