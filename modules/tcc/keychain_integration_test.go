//go:build integration && darwin

package tcc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Drives the real `security` tool. Pointed at a keychain path that does not
// exist, unlocking with no password is refused - the expected, valid telemetry
// this module exists to generate. (dump-keychain ignores a bad path and dumps a
// default store, so its verdict is environment-dependent and only checked to be
// a non-error observation.)
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

	// Unlock of a nonexistent keychain with no password is reliably refused.
	unlock := events[1]
	if unlock.ResolvedOutcome() != module.OutcomeDenied {
		t.Errorf("unlock outcome = %q, want denied", unlock.ResolvedOutcome())
	}
	if unlock.Details["result"] != "denied" {
		t.Errorf("unlock result detail = %v, want denied", unlock.Details["result"])
	}

	// The dump attempt must at least run and be recorded as a real observation,
	// never a macnoise error.
	dump := events[2]
	if o := dump.ResolvedOutcome(); o != module.OutcomeExecuted && o != module.OutcomeDenied {
		t.Errorf("dump outcome = %q, want executed or denied", o)
	}
}
