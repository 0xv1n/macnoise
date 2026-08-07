package tcc

import (
	"errors"
	"io/fs"
	"testing"
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
