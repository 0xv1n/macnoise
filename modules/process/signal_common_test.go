package process

import (
	"strings"
	"testing"
)

func TestStampCommandIncludesRunID(t *testing.T) {
	command := stampCommand("sleep 5", "deadbeef01234567")
	if !strings.Contains(command, "# mn:deadbeef01234567") {
		t.Fatalf("stamped command = %q", command)
	}
}

func TestStampCommandWithoutRunIDIsUnchanged(t *testing.T) {
	const command = "sleep 5"
	if got := stampCommand(command, ""); got != command {
		t.Fatalf("stamped command = %q, want %q", got, command)
	}
}
