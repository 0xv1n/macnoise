package tcc

import (
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestKeychainDryRun(t *testing.T) {
	steps := (&tccKeychain{}).DryRun(module.Params{"keychain_path": "/tmp/victim.keychain-db"})
	if len(steps) != 3 {
		t.Fatalf("dry run = %v, want 3 steps", steps)
	}
	joined := strings.Join(steps, "\n")
	for _, want := range []string{"list-keychains", "unlock-keychain", "dump-keychain", "/tmp/victim.keychain-db"} {
		if !strings.Contains(joined, want) {
			t.Errorf("dry run missing %q:\n%s", want, joined)
		}
	}
}
