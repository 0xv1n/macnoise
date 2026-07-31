//go:build darwin

package process

import "testing"

// sanitizeOsascriptOutput must redact captured output whenever the script
// solicited hidden/masked input, in both AppleScript and JXA form - a
// confused operator could type a real password into what looks like a
// system prompt, and it must never reach telemetry or audit output.
func TestSanitizeOsascriptOutput(t *testing.T) {
	tests := []struct {
		name   string
		script string
		out    string
		want   string
	}{
		{
			name:   "AppleScript with hidden answer is redacted",
			script: `display dialog "Enter password" default answer "" with hidden answer`,
			out:    `{text returned:"hunter2", button returned:"OK"}`,
			want:   redactedOutput,
		},
		{
			name:   "JXA hiddenAnswer option is redacted",
			script: `app.displayDialog("Enter password", {defaultAnswer: "", hiddenAnswer: true})`,
			out:    `{textReturned: "hunter2", buttonReturned: "OK"}`,
			want:   redactedOutput,
		},
		{
			name:   "case and spacing variants are still caught",
			script: `display dialog "x" WITH   HIDDEN   ANSWER`,
			out:    `whatever`,
			want:   redactedOutput,
		},
		{
			name:   "ordinary script output passes through unchanged",
			script: `do shell script "id"`,
			out:    `uid=501(operator) gid=20(staff)`,
			want:   `uid=501(operator) gid=20(staff)`,
		},
		{
			name:   "plain visible-answer dialog is not redacted",
			script: `display dialog "pick one" buttons {"A","B"}`,
			out:    `{button returned:"A"}`,
			want:   `{button returned:"A"}`,
		},
		{
			name:   "notification script is not redacted",
			script: `display notification "macnoise telemetry" with title "MacNoise"`,
			out:    ``,
			want:   ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeOsascriptOutput(tt.script, tt.out)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
