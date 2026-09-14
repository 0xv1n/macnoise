package credential

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestParseKeychainPaths(t *testing.T) {
	out := []byte("    \"/Users/test/Library/Keychains/login.keychain-db\"\n    \"/Library/Keychains/System.keychain\"\n")
	want := []string{"/Users/test/Library/Keychains/login.keychain-db", "/Library/Keychains/System.keychain"}
	if got := parseKeychainPaths(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
}

func TestKeychainCommandOutcomeDoesNotLaunderFailures(t *testing.T) {
	exitErr := &exec.ExitError{}
	tests := []struct {
		name   string
		err    error
		output string
		want   module.Outcome
	}{
		{name: "success", want: module.OutcomeExecuted},
		{name: "missing keychain", err: exitErr, output: "The specified keychain could not be found.", want: module.OutcomeIndeterminate},
		{name: "wrong passphrase", err: exitErr, output: "The user name or passphrase you entered is not correct.", want: module.OutcomeDenied},
		{name: "unexpected command failure", err: exitErr, output: "invalid database", want: module.OutcomeError},
		{name: "executable missing", err: errors.New("security executable missing"), want: module.OutcomeError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keychainCommandOutcome(tt.err, tt.output); got != tt.want {
				t.Fatalf("outcome = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKeychainContract(t *testing.T) {
	gen := &credKeychain{}
	if gen.Info().Category != module.CategoryCredential || gen.Info().Privileges != module.PrivilegeNone {
		t.Fatalf("info = %+v", gen.Info())
	}
	steps := strings.Join(gen.DryRun(module.Params{"keychain_path": "/tmp/victim.keychain-db", "password": "secret"}), "\n")
	for _, want := range []string{"list-keychains", "unlock-keychain", "dump-keychain", "/tmp/victim.keychain-db", module.RedactedValue} {
		if !strings.Contains(steps, want) {
			t.Errorf("dry run missing %q: %s", want, steps)
		}
	}
	if strings.Contains(steps, "secret") {
		t.Fatal("dry run exposed the keychain password")
	}
}
