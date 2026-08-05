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

func TestSvcLaunchDaemon_PrereqRequiresRoot(t *testing.T) {
	s := &svcLaunchDaemon{}
	err := s.CheckPrereqs()
	if os.Getuid() == 0 {
		if err != nil {
			t.Errorf("CheckPrereqs as root: %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Error("CheckPrereqs must reject a non-root process, this gate is what keeps Generate from writing to /Library/LaunchDaemons")
	}
}

// Writes to /Library/LaunchDaemons, so this only runs under sudo. CI runs the
// integration job as the unprivileged runner user, which means this module's
// Generate/Cleanup cycle is exercised only when someone runs the suite as root
// on a real Mac.
func TestSvcLaunchDaemon_GenerateAndCleanup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: writes to /Library/LaunchDaemons")
	}

	const label = "com.macnoise.integrationtest.daemon"
	plistPath := filepath.Join("/Library/LaunchDaemons", label+".plist")
	t.Cleanup(func() { _ = os.Remove(plistPath) })

	s := &svcLaunchDaemon{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"label": label, "program": "/usr/bin/true"}
	if err := s.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	f, err := os.Open(plistPath)
	if err != nil {
		t.Fatalf("LaunchDaemon plist not created: %v", err)
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
		if ev.EventType == "launchdaemon_create" && ev.Success {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Error("expected a successful launchdaemon_create event")
	}

	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Errorf("expected plist to be removed after Cleanup, stat err = %v", err)
	}
}
