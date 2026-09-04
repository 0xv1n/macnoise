//go:build integration && darwin

package tcc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Drives the real `security` tool. Pointed at a keychain path that does not
// exist, the unlock and dump attempts are refused - which is the expected,
// valid telemetry this module exists to generate - while list-keychains still
// enumerates the session keychains.
func TestKeychainGenerate_EmitsThreeProbes(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "nope.keychain-db")

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := (&tccKeychain{}).Generate(context.Background(), module.Params{"keychain_path": bogus}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	wantOrder := []string{"keychain_list", "keychain_unlock_attempt", "keychain_dump_attempt"}
	if len(events) != len(wantOrder) {
		t.Fatalf("emitted %d events, want %d: %+v", len(events), len(wantOrder), events)
	}
	for i, want := range wantOrder {
		if events[i].EventType != want {
			t.Errorf("event %d type = %q, want %q", i, events[i].EventType, want)
		}
	}

	// Unlock and dump against a nonexistent keychain with no password must be
	// refused, not error out macnoise.
	for _, ev := range events[1:] {
		if ev.ResolvedOutcome() != module.OutcomeDenied {
			t.Errorf("%s outcome = %q, want denied", ev.EventType, ev.ResolvedOutcome())
		}
		if ev.Details["result"] != "denied" {
			t.Errorf("%s result detail = %v, want denied", ev.EventType, ev.Details["result"])
		}
	}
}
