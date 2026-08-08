package output_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

func outcomeModuleInfo() module.ModuleInfo {
	return module.ModuleInfo{Name: "test_module", Category: module.CategoryTCC}
}

// A denied action and a broken tool must not look the same. Before the outcome
// field the only way to express "the probe was refused" was Success plus prose,
// which a consumer cannot filter on.
func TestWithOutcomeKeepsSuccessInSync(t *testing.T) {
	cases := []struct {
		outcome     module.Outcome
		wantSuccess bool
	}{
		{module.OutcomeExecuted, true},
		{module.OutcomeDenied, true},
		{module.OutcomeIndeterminate, true},
		{module.OutcomeError, false},
	}

	for _, tc := range cases {
		ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", true, "probing")
		ev = output.WithOutcome(ev, tc.outcome, nil)

		if ev.Outcome != tc.outcome {
			t.Errorf("%s: outcome = %q, want %q", tc.outcome, ev.Outcome, tc.outcome)
		}
		if ev.Success != tc.wantSuccess {
			t.Errorf("%s: success = %v, want %v", tc.outcome, ev.Success, tc.wantSuccess)
		}
	}
}

// The error recorded alongside a denial explains the refusal. It must not flip
// the event into a tool failure the way WithError does.
func TestWithOutcomeErrorDoesNotMarkFailure(t *testing.T) {
	ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", true, "probing")
	ev = output.WithOutcome(ev, module.OutcomeDenied, errors.New("permission denied"))

	if ev.Error != "permission denied" {
		t.Errorf("error = %q, want %q", ev.Error, "permission denied")
	}
	if !ev.Success {
		t.Error("a denial recorded an error and was marked as a macnoise failure")
	}
	if ev.Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeDenied)
	}
}

func TestWithErrorSetsErrorOutcome(t *testing.T) {
	ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", true, "probing")
	ev = output.WithError(ev, errors.New("i/o error"))

	if ev.Outcome != module.OutcomeError {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeError)
	}
	if ev.Success {
		t.Error("WithError left Success true")
	}
}

// Modules overwhelmingly never set an outcome, so an emitted record has to
// carry one anyway or a consumer cannot rely on the field being there.
func TestEmittedJSONAlwaysCarriesOutcome(t *testing.T) {
	cases := []struct {
		name string
		ev   module.TelemetryEvent
		want string
	}{
		{"unset and successful", module.TelemetryEvent{Success: true}, "executed"},
		{"unset and failed", module.TelemetryEvent{Success: false}, "error"},
		{"explicitly denied", module.TelemetryEvent{Success: true, Outcome: module.OutcomeDenied}, "denied"},
		{
			"explicitly indeterminate",
			module.TelemetryEvent{Success: true, Outcome: module.OutcomeIndeterminate},
			"indeterminate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			output.NewEmitter(output.FormatJSONL, &buf).Emit(tc.ev)

			var m map[string]any
			if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if got := m["outcome"]; got != tc.want {
				t.Errorf("outcome = %v, want %q", got, tc.want)
			}
		})
	}
}

func TestHumanMarkerPerOutcome(t *testing.T) {
	cases := []struct {
		outcome module.Outcome
		want    string
	}{
		{module.OutcomeExecuted, "[+]"},
		{module.OutcomeDenied, "[-]"},
		{module.OutcomeIndeterminate, "[?]"},
		{module.OutcomeError, "[!]"},
	}

	for _, tc := range cases {
		var buf bytes.Buffer
		ev := sampleEvent()
		ev.Outcome = tc.outcome
		output.NewEmitter(output.FormatHuman, &buf).Emit(ev)

		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("%s: expected marker %s, got %q", tc.outcome, tc.want, buf.String())
		}
	}
}

func TestSchemaVersionBumped(t *testing.T) {
	if output.SchemaVersion != "1.1" {
		t.Errorf("SchemaVersion = %q, want 1.1 (outcome field added)", output.SchemaVersion)
	}
}
