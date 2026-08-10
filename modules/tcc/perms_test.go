package tcc

import (
	"errors"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A refused Accessibility read and a missing GUI session are not macnoise
// faults. The osascript error number is the discriminator, the same shape the
// svc_login_item classifier uses for a different TCC gate.
func TestAccessibilityOutcome(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		output string
		want   module.Outcome
	}{
		{"granted", nil, "Apple, Finder, File, Edit", module.OutcomeExecuted},
		{
			name:   "not trusted for accessibility is denied",
			err:    errors.New("exit status 1"),
			output: "execution error: System Events got an error: osascript is not allowed assistive access. (-1719)",
			want:   module.OutcomeDenied,
		},
		{
			// No "assistive access" text, so this isolates the -1719 marker:
			// break that check and this case falls through to error.
			name:   "bare -1719 code is denied",
			err:    errors.New("exit status 1"),
			output: "execution error: (-1719)",
			want:   module.OutcomeDenied,
		},
		{
			name:   "newer assistive-access code is denied",
			err:    errors.New("exit status 1"),
			output: "execution error: ... (-25211)",
			want:   module.OutcomeDenied,
		},
		{
			name:   "no GUI session is indeterminate",
			err:    errors.New("exit status 1"),
			output: "execution error: An error of type -10810 has occurred. (-10810)",
			want:   module.OutcomeIndeterminate,
		},
		{
			name:   "any other failure is a tool error",
			err:    errors.New("exit status 1"),
			output: "execution error: something else (-2700)",
			want:   module.OutcomeError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accessibilityOutcome(tt.err, tt.output); got != tt.want {
				t.Errorf("accessibilityOutcome(%v, %q) = %q, want %q", tt.err, tt.output, got, tt.want)
			}
		})
	}
}

// Screen capture cannot be a granted/denied classifier from the CLI, so it must
// only ever report that the attempt ran or could not be attempted - never a
// permission verdict.
func TestScreenCaptureOutcome(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		bytes int64
		want  module.Outcome
	}{
		{"captured bytes", nil, 3494, module.OutcomeExecuted},
		{"ran but wrote nothing", nil, 0, module.OutcomeIndeterminate},
		{"command failed", errors.New("exit status 1"), 0, module.OutcomeIndeterminate},
		{"failed despite a stale file", errors.New("no display"), 1024, module.OutcomeIndeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := screenCaptureOutcome(tt.err, tt.bytes)
			if got != tt.want {
				t.Errorf("screenCaptureOutcome(%v, %d) = %q, want %q", tt.err, tt.bytes, got, tt.want)
			}
			// The invariant that keeps the module honest: it must never emit a
			// granted or denied verdict for screen recording.
			if got == module.OutcomeDenied {
				t.Error("screen capture must not report a denied verdict it cannot determine")
			}
		})
	}
}

func TestAccessibilityDryRunMatchesProbe(t *testing.T) {
	lines := (&tccAccessibility{}).DryRun(nil)
	if len(lines) != 1 || !strings.Contains(lines[0], accessibilityProbeScript()) {
		t.Errorf("dry run does not advertise the probe script: %v", lines)
	}
}
