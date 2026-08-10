package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A name or path with a quote must not break out of the AppleScript literal.
// This is the es_process quoting failure in a different interpreter: an
// unescaped quote silently changes the statement rather than erroring.
func TestAppleScriptString(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`plain`, `"plain"`},
		{`with "quote"`, `"with \"quote\""`},
		{`back\slash`, `"back\\slash"`},
		{`/usr/bin/true`, `"/usr/bin/true"`},
	}
	for _, tt := range tests {
		if got := appleScriptString(tt.in); got != tt.want {
			t.Errorf("appleScriptString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The make command must name the login item and its target, and stay a single
// System Events statement.
func TestMakeLoginItemScript(t *testing.T) {
	got := makeLoginItemScript("MacNoiseLoginItem", "/usr/bin/true")
	for _, want := range []string{
		`tell application "System Events"`,
		`name:"MacNoiseLoginItem"`,
		`path:"/usr/bin/true"`,
		`hidden:false`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("make script missing %q\ngot: %s", want, got)
		}
	}
}

func TestDeleteLoginItemScriptTargetsByName(t *testing.T) {
	got := deleteLoginItemScript("MacNoiseLoginItem")
	if !strings.Contains(got, `whose name is "MacNoiseLoginItem"`) {
		t.Errorf("delete script does not target by name\ngot: %s", got)
	}
}

// The whole point of the module and of the day-18 outcome field: a refusal or a
// missing GUI session is not a macnoise failure and must not be classified as
// one.
func TestLoginItemOutcome(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		output string
		want   module.Outcome
	}{
		{"success", nil, "", module.OutcomeExecuted},
		{
			name:   "automation not authorized is denied",
			err:    errors.New("exit status 1"),
			output: "execution error: Not authorized to send Apple events to System Events. (-1743)",
			want:   module.OutcomeDenied,
		},
		{
			name:   "bare -1743 is denied",
			err:    errors.New("exit status 1"),
			output: "execution error: (-1743)",
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
			output: "execution error: something unexpected (-2700)",
			want:   module.OutcomeError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginItemOutcome(tt.err, tt.output); got != tt.want {
				t.Errorf("loginItemOutcome(%v, %q) = %q, want %q", tt.err, tt.output, got, tt.want)
			}
		})
	}
}

func TestParseLoginItemNames(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "MacNoiseLoginItem", []string{"MacNoiseLoginItem"}},
		{"multiple", "Dropbox, iTunesHelper, MacNoiseLoginItem", []string{"Dropbox", "iTunesHelper", "MacNoiseLoginItem"}},
		{"trailing whitespace", "  Dropbox ,  Rectangle  ", []string{"Dropbox", "Rectangle"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLoginItemNames(tt.out)
			if len(got) != len(tt.want) {
				t.Fatalf("parseLoginItemNames(%q) = %v, want %v", tt.out, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("name[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDryRunMatchesExecutedScripts(t *testing.T) {
	lines := (&svcLoginItem{}).DryRun(nil)
	joined := strings.Join(lines, "\n")

	for _, want := range []string{
		makeLoginItemScript("MacNoiseLoginItem", "/usr/bin/true"),
		deleteLoginItemScript("MacNoiseLoginItem"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run does not advertise %q\ngot:\n%s", want, joined)
		}
	}
}

// Cleanup must be a no-op when nothing was added, or a refused run on a headless
// host reports a delete failure for an item that never existed.
func TestCleanupIsNoOpWhenNothingAdded(t *testing.T) {
	if err := (&svcLoginItem{}).Cleanup(); err != nil {
		t.Errorf("Cleanup with nothing added returned %v", err)
	}
	if err := (&svcLoginItem{name: "X", added: false}).Cleanup(); err != nil {
		t.Errorf("Cleanup with added=false returned %v", err)
	}
}
