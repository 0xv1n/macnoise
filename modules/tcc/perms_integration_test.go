//go:build integration && darwin

package tcc

import (
	"context"
	"os"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runPerm(t *testing.T, gen module.Generator) module.TelemetryEvent {
	t.Helper()
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	if err := gen.Generate(context.Background(), module.Params{}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

// The Accessibility probe drives System Events, which needs a GUI session and
// consent that neither ssh nor a headless runner is guaranteed to have. The
// contract everywhere is that it never reports a macnoise fault for an
// environment that merely refused or could not be reached.
func TestAccessibility_ClassifiesEnvironmentWithoutFailing(t *testing.T) {
	ev := runPerm(t, &tccAccessibility{})

	if ev.EventType != "tcc_accessibility_probe" {
		t.Errorf("event type = %q, want tcc_accessibility_probe", ev.EventType)
	}
	switch ev.Outcome {
	case module.OutcomeExecuted, module.OutcomeDenied, module.OutcomeIndeterminate:
		if !ev.Success {
			t.Errorf("outcome %q left Success false; only a real fault should", ev.Outcome)
		}
	default:
		t.Errorf("adding reported an unexpected outcome %q: %s", ev.Outcome, ev.Error)
	}
}

// Screen capture must never claim a permission verdict, only that the attempt
// ran or could not be attempted. Over ssh there is no display, so this is
// typically indeterminate; in a GUI session it is executed. Denied must never
// appear.
func TestScreenRecording_NeverClaimsAVerdict(t *testing.T) {
	ev := runPerm(t, &tccScreenRecording{})

	if ev.EventType != "screen_capture_attempt" {
		t.Errorf("event type = %q, want screen_capture_attempt", ev.EventType)
	}
	if ev.Outcome != module.OutcomeExecuted && ev.Outcome != module.OutcomeIndeterminate {
		t.Errorf("outcome = %q, want executed or indeterminate (never a grant verdict)", ev.Outcome)
	}
	if !ev.Success {
		t.Errorf("Success = false; a capture attempt is not a macnoise fault: %s", ev.Error)
	}
	if ev.Details["permission"] != "indeterminate" {
		t.Errorf("permission = %v, want indeterminate (the CLI cannot read the grant)", ev.Details["permission"])
	}
}

// The granted and executed paths need a real GUI session with the permissions
// actually granted to the responsible app, so they are gated behind an env var
// and run manually in a console session rather than over ssh or CI.
func TestPerms_GrantedPathsWithGUISession(t *testing.T) {
	if os.Getenv("MACNOISE_GUI_TESTS") == "" {
		t.Skip("set MACNOISE_GUI_TESTS=1 in a GUI session with Accessibility and Screen Recording granted")
	}

	ax := runPerm(t, &tccAccessibility{})
	if ax.Outcome != module.OutcomeExecuted {
		t.Errorf("accessibility outcome = %q (%s); expected executed with Accessibility granted", ax.Outcome, ax.Error)
	}

	sc := runPerm(t, &tccScreenRecording{})
	if sc.Outcome != module.OutcomeExecuted {
		t.Errorf("screen capture outcome = %q (%s); expected executed in a GUI session", sc.Outcome, sc.Error)
	}
	if b, _ := sc.Details["bytes_captured"].(int64); b <= 0 {
		t.Errorf("bytes_captured = %v, want > 0", sc.Details["bytes_captured"])
	}
}
