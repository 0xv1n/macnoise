package output_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

func outcomeModuleInfo() module.ModuleInfo {
	return module.ModuleInfo{Name: "test_module", Category: module.CategoryTCC}
}

// A denied action and a broken tool must not look the same.
func TestWithOutcomeSetsAuthoritativeOutcome(t *testing.T) {
	for _, outcome := range []module.Outcome{
		module.OutcomeExecuted,
		module.OutcomeDenied,
		module.OutcomeIndeterminate,
		module.OutcomeError,
	} {
		ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", module.OutcomeExecuted, module.Resource("tcc", "fda", "/tmp/TCC.db"), "probing")
		ev = output.WithOutcome(ev, outcome, nil)

		if ev.Outcome != outcome {
			t.Errorf("%s: outcome = %q, want %q", outcome, ev.Outcome, outcome)
		}
	}
}

// The error recorded alongside a denial explains the refusal. It must not flip
// the event into a tool failure the way WithError does.
func TestWithOutcomeErrorDoesNotMarkFailure(t *testing.T) {
	ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", module.OutcomeExecuted, module.Resource("tcc", "fda", "/tmp/TCC.db"), "probing")
	ev = output.WithOutcome(ev, module.OutcomeDenied, errors.New("permission denied"))

	if ev.Error != "permission denied" {
		t.Errorf("error = %q, want %q", ev.Error, "permission denied")
	}
	if ev.Outcome != module.OutcomeDenied {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeDenied)
	}
}

func TestWithErrorSetsErrorOutcome(t *testing.T) {
	ev := output.NewEvent(outcomeModuleInfo(), "tcc_fda_probe", module.OutcomeExecuted, module.Resource("tcc", "fda", "/tmp/TCC.db"), "probing")
	ev = output.WithError(ev, errors.New("i/o error"))

	if ev.Outcome != module.OutcomeError {
		t.Errorf("outcome = %q, want %q", ev.Outcome, module.OutcomeError)
	}
}

func TestEmitterRejectsMissingOutcome(t *testing.T) {
	var buf bytes.Buffer
	err := output.NewEmitter(output.FormatJSONL, &buf).Emit(module.TelemetryEvent{
		Subject: module.Resource("test", "subject", ""),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid outcome") {
		t.Fatalf("Emit() error = %v, want invalid outcome", err)
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
		if err := output.NewEmitter(output.FormatHuman, &buf).Emit(ev); err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("%s: expected marker %s, got %q", tc.outcome, tc.want, buf.String())
		}
	}
}

func TestSchemaVersionBumped(t *testing.T) {
	if output.SchemaVersion != "2.0" {
		t.Errorf("SchemaVersion = %q, want 2.0", output.SchemaVersion)
	}
}
