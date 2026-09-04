package tcc

import (
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestContactsDryRun(t *testing.T) {
	steps := (&tccContacts{}).DryRun(module.Params{})
	if len(steps) != 1 {
		t.Fatalf("dry run = %v, want 1 line", steps)
	}
	if !strings.Contains(steps[0], "AddressBook") {
		t.Errorf("dry-run line %q should name the AddressBook probe", steps[0])
	}
}
