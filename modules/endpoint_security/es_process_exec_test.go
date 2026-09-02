//go:build !windows

package endpointsecurity

import (
	"os/exec"
	"strings"
	"testing"
)

// Excluded on Windows: Go's os/exec there builds a command-line string that
// MSYS2/Cygwin-style sh.exe re-parses differently than real POSIX sh, which
// doesn't reflect this module's actual (macOS) target.
func TestBuildExecChainArgs_ActuallyExecutes(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}

	for _, depth := range []int{3, 5, 10} {
		args := buildExecChainArgs(depth, "abc123")
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Errorf("depth=%d: exec failed: %v (output: %q)", depth, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); got != "es_exit_abc123" {
			t.Errorf("depth=%d: output = %q, want %q", depth, got, "es_exit_abc123")
		}
	}
}
