package audit

import (
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestStatusForOutcome(t *testing.T) {
	cases := []struct {
		outcome    module.Outcome
		severityID int
		severity   string
		statusID   int
		status     string
	}{
		{module.OutcomeExecuted, 1, "Informational", 1, "Success"},
		{module.OutcomeDenied, 1, "Informational", 2, "Failure"},
		{module.OutcomeIndeterminate, 1, "Informational", 0, "Unknown"},
		{module.OutcomeError, 3, "Medium", 2, "Failure"},
	}

	for _, tc := range cases {
		got := statusForOutcome(tc.outcome)
		want := OutcomeStatus{tc.severityID, tc.severity, tc.statusID, tc.status}
		if got != want {
			t.Errorf("statusForOutcome(%q) = %+v, want %+v", tc.outcome, got, want)
		}
	}
}

// The bug this replaced: severity keyed off Success alone, and the TCC probes
// set Success true on a genuine I/O failure, so a broken probe was written to
// the audit log as Informational.
func TestErrorOutcomeIsTheOnlyElevatedSeverity(t *testing.T) {
	for _, o := range []module.Outcome{module.OutcomeExecuted, module.OutcomeDenied, module.OutcomeIndeterminate} {
		if st := statusForOutcome(o); st.SeverityID != 1 {
			t.Errorf("%q raised severity to %d; only a macnoise fault should", o, st.SeverityID)
		}
	}
	if st := statusForOutcome(module.OutcomeError); st.SeverityID != 3 {
		t.Errorf("error severity = %d, want 3", st.SeverityID)
	}
}

// OCSF status describes the reported activity, so a refused action is a Failure
// of that activity even though macnoise worked. The two are told apart by
// severity and by unmapped.outcome, not by status.
func TestDeniedAndErrorShareStatusButNotOutcome(t *testing.T) {
	denied := statusForOutcome(module.OutcomeDenied)
	failed := statusForOutcome(module.OutcomeError)

	if denied.StatusID != failed.StatusID {
		t.Errorf("denied status %d and error status %d should both be OCSF Failure", denied.StatusID, failed.StatusID)
	}
	if denied.SeverityID == failed.SeverityID {
		t.Error("denied and error are indistinguishable: same status and same severity")
	}
}

func TestLogEventRecordsOutcome(t *testing.T) {
	cases := []struct {
		name        string
		ev          module.TelemetryEvent
		wantOutcome string
		wantStatus  string
	}{
		{
			name:        "denial is not reported as a successful activity",
			ev:          module.TelemetryEvent{Category: "tcc", EventType: "tcc_fda_probe", Success: true, Outcome: module.OutcomeDenied},
			wantOutcome: "denied",
			wantStatus:  "Failure",
		},
		{
			name:        "probe error is not reported as a success",
			ev:          module.TelemetryEvent{Category: "tcc", EventType: "tcc_fda_probe", Success: true, Outcome: module.OutcomeError},
			wantOutcome: "error",
			wantStatus:  "Failure",
		},
		{
			name:        "absent target is unknown, not failed",
			ev:          module.TelemetryEvent{Category: "tcc", EventType: "tcc_fda_probe", Success: true, Outcome: module.OutcomeIndeterminate},
			wantOutcome: "indeterminate",
			wantStatus:  "Unknown",
		},
		{
			name:        "an event with no outcome still records one",
			ev:          module.TelemetryEvent{Category: "tcc", EventType: "tcc_fda_probe", Success: true},
			wantOutcome: "executed",
			wantStatus:  "Success",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := recordFor(t, tc.ev)

			if rec.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", rec.Status, tc.wantStatus)
			}
			um, ok := rec.Unmapped.(map[string]any)
			if !ok {
				t.Fatalf("unmapped is %T, want an object", rec.Unmapped)
			}
			if um["outcome"] != tc.wantOutcome {
				t.Errorf("unmapped.outcome = %v, want %q", um["outcome"], tc.wantOutcome)
			}
		})
	}
}

// recordFor round-trips ev through a real Logger and returns the single record
// it wrote, so the assertions run against serialised JSON rather than the
// in-memory struct.
func recordFor(t *testing.T, ev module.TelemetryEvent) Record {
	t.Helper()

	l, path := newTestLogger(t)
	l.LogEvent(ev, module.ModuleInfo{Name: "tcc_fda", Category: module.CategoryTCC}, nil)
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	records := readRecords(t, path)
	if len(records) != 1 {
		t.Fatalf("wrote %d records, want 1", len(records))
	}
	return records[0]
}
