package process

import (
	"strings"
	"testing"
)

func TestStampCommand_WithRunID(t *testing.T) {
	cmd := stampCommand("echo hi", "deadbeef01234567")
	if !strings.Contains(cmd, "deadbeef01234567") {
		t.Errorf("run ID missing from command: %s", cmd)
	}
	if !strings.HasPrefix(cmd, "echo hi") {
		t.Errorf("original command not preserved: %s", cmd)
	}
	if !strings.Contains(cmd, "#") {
		t.Errorf("run ID should be a shell comment: %s", cmd)
	}
}

func TestStampCommand_WithoutRunID(t *testing.T) {
	cmd := stampCommand("echo hi", "")
	if cmd != "echo hi" {
		t.Errorf("unstamped command = %q, want %q", cmd, "echo hi")
	}
}
