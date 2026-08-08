package tcc

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A missing resource must never be reported as a denial. Both probes used to
// collapse every error into "denied", so a machine that had simply never used
// Contacts reported a TCC refusal that never happened.
func TestClassifyProbe(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want probeOutcome
	}{
		{"no error is granted", nil, probeGranted},
		{"missing path is absent", &fs.PathError{Op: "open", Err: fs.ErrNotExist}, probeAbsent},
		{"permission refusal is denied", &fs.PathError{Op: "open", Err: fs.ErrPermission}, probeDenied},
		{"unexpected failure is not a denial", &fs.PathError{Op: "open", Err: errors.New("input/output error")}, probeError},
		{"bare error is not a denial", errors.New("boom"), probeError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyProbe(tt.err); got != tt.want {
				t.Errorf("classifyProbe(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// The probe result has to reach the event schema, not just details["result"].
// A consumer filtering on outcome should see a refusal as denied and a missing
// resource as indeterminate, without knowing this module exists.
func TestEventOutcome(t *testing.T) {
	tests := []struct {
		probe probeOutcome
		want  module.Outcome
	}{
		{probeGranted, module.OutcomeExecuted},
		{probeDenied, module.OutcomeDenied},
		{probeAbsent, module.OutcomeIndeterminate},
		{probeError, module.OutcomeError},
	}

	for _, tt := range tests {
		if got := eventOutcome(tt.probe); got != tt.want {
			t.Errorf("eventOutcome(%q) = %q, want %q", tt.probe, got, tt.want)
		}
	}
}
