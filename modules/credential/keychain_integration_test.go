//go:build integration && darwin

package credential

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestKeychainGenerateAbsentTargetIsIndeterminate(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "absent.keychain-db")
	var events []module.TelemetryEvent
	gen := &credKeychain{}
	err := gen.Generate(context.Background(), module.Params{"keychain_path": bogus}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	wantTypes := []string{"keychain_list", "keychain_unlock_attempt", "keychain_dump_attempt"}
	for index, ev := range events {
		if ev.EventType != wantTypes[index] {
			t.Errorf("event %d type = %q, want %q", index, ev.EventType, wantTypes[index])
		}
		if !slices.Contains(gen.Info().EventTypes, ev.EventType) {
			t.Errorf("emitted event type %q is not declared", ev.EventType)
		}
		if index > 0 && ev.Outcome != module.OutcomeIndeterminate {
			t.Errorf("%s outcome = %q, want indeterminate", ev.EventType, ev.Outcome)
		}
	}
}
