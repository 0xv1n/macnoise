//go:build integration && darwin

package credential

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestKeychainGenerateAbsentTargetIsIndeterminate(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "absent.keychain-db")
	var events []module.TelemetryEvent
	err := (&credKeychain{}).Generate(context.Background(), module.Params{"keychain_path": bogus}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %+v", events)
	}
	for _, ev := range events[1:] {
		if ev.Outcome != module.OutcomeIndeterminate {
			t.Errorf("%s outcome = %q, want indeterminate", ev.EventType, ev.Outcome)
		}
	}
}
