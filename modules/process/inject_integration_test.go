//go:build integration && darwin

package process

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runInject(t *testing.T, params module.Params) module.TelemetryEvent {
	t.Helper()
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := (&procInject{}).Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

// The default target must be one dyld will actually inject into. The test
// binary itself stands in for macnoise here: both are Go-built and only ad-hoc
// signed, so they exercise the same dyld path.
func TestProcInject_DefaultTargetIsHonouredByDyld(t *testing.T) {
	ev := runInject(t, module.Params{"dylib_path": filepath.Join(t.TempDir(), "absent.dylib")})

	if got := ev.Details["outcome"]; got != "honored" {
		t.Errorf("outcome = %v, want honored; dyld did not act on DYLD_INSERT_LIBRARIES for the default target", got)
	}
	if !ev.Success {
		t.Error("Success = false; dyld aborting the child is the successful injection path, not a failure")
	}
}

// The regression this module existed with: /usr/bin/true is protected, so the
// variable never reaches dyld and no injection occurs, yet the module used to
// report the spawn as a success without qualification.
func TestProcInject_ProtectedTargetIsReportedStripped(t *testing.T) {
	ev := runInject(t, module.Params{
		"target":     "/usr/bin/true",
		"dylib_path": filepath.Join(t.TempDir(), "absent.dylib"),
	})

	if got := ev.Details["outcome"]; got != "stripped" {
		t.Errorf("outcome = %v, want stripped for the SIP-protected /usr/bin/true", got)
	}
	if ev.Details["target"] != "/usr/bin/true" {
		t.Errorf("target = %v, want /usr/bin/true", ev.Details["target"])
	}
}

// The protection is a property of system binaries generally, not a quirk of
// /usr/bin/true, so a second one must classify the same way.
func TestProcInject_OtherSystemBinaryAlsoStripped(t *testing.T) {
	ev := runInject(t, module.Params{
		"target":     "/bin/ls",
		"dylib_path": filepath.Join(t.TempDir(), "absent.dylib"),
	})

	if got := ev.Details["outcome"]; got != "stripped" {
		t.Errorf("outcome = %v, want stripped for /bin/ls", got)
	}
}
