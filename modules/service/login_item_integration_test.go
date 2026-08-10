//go:build integration && darwin

package service

import (
	"context"
	"os"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runLoginItem(t *testing.T, e *svcLoginItem, params module.Params) module.TelemetryEvent {
	t.Helper()

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	t.Cleanup(func() { _ = e.Cleanup() })

	if err := e.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

// Adding a login item drives System Events, which needs a GUI (Aqua) session
// and Automation consent that neither the ssh path to the test box nor a
// headless CI runner is guaranteed to have. The contract that must hold
// everywhere is that the module never reports a broken tool for an environment
// that merely refused or could not be reached: the outcome is one of the four
// known values, and Success tracks it.
func TestLoginItem_ClassifiesEnvironmentWithoutFailing(t *testing.T) {
	ev := runLoginItem(t, &svcLoginItem{}, module.Params{"name": "MacNoiseLoginItemTest"})

	if ev.EventType != "login_item_add" {
		t.Errorf("event type = %q, want login_item_add", ev.EventType)
	}
	switch ev.Outcome {
	case module.OutcomeExecuted, module.OutcomeDenied, module.OutcomeIndeterminate:
		if !ev.Success {
			t.Errorf("outcome %q left Success false; only a real macnoise fault should", ev.Outcome)
		}
	case module.OutcomeError:
		t.Errorf("adding a login item reported a macnoise failure: %s", ev.Error)
	default:
		t.Errorf("unexpected outcome %q", ev.Outcome)
	}

	if got := ev.Details["es_event"]; got != "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD" {
		t.Errorf("es_event = %v, want ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD", got)
	}
}

// The full add -> verify -> cleanup cycle only works with a real GUI session
// and Automation consent, so it is gated behind an opt-in env var and run
// manually via the RustDesk GUI on the test box rather than over ssh or CI.
func TestLoginItem_FullCycleWithGUISession(t *testing.T) {
	if os.Getenv("MACNOISE_GUI_TESTS") == "" {
		t.Skip("set MACNOISE_GUI_TESTS=1 to run in a real GUI session with Automation consent granted")
	}

	name := "MacNoiseLoginItemGUITest"
	e := &svcLoginItem{}
	ev := runLoginItem(t, e, module.Params{"name": name})

	if ev.Outcome != module.OutcomeExecuted {
		t.Fatalf("outcome = %q (%s); expected executed in a consented GUI session", ev.Outcome, ev.Error)
	}
	if present, ok := ev.Details["verified_present"].(bool); !ok || !present {
		t.Errorf("login item %q was not found in the list after add", name)
	}
	if err := e.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	present, err := e.loginItemPresent(context.Background(), name)
	if err != nil {
		t.Fatalf("list after cleanup: %v", err)
	}
	if present {
		t.Errorf("login item %q survived Cleanup", name)
	}
}
