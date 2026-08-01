//go:build !windows

package endpointsecurity

import (
	"os/exec"
	"strings"
	"testing"
)

// The whole point of buildExecChainArgs is that the chain actually executes
// correctly - this runs it for real via the exact exec.Command call
// Generate uses, at the module's default (3), a middling value (5), and its
// own clamp ceiling (10). Verified independently against real POSIX sh up
// to depth 50 during development; this locks in the depths that matter.
//
// Windows-excluded: Go's os/exec on Windows reconstructs a command-line
// string for CreateProcess, and MSYS2/Cygwin-style sh.exe builds re-parse
// that string with their own (non-POSIX-matching) conventions - a
// Windows-hosted sh.exe failed this exact test during development even
// though the fix is correct, which isn't a signal about the fix itself
// since this module only ever runs against a real macOS target.
func TestBuildExecChainArgs_ActuallyExecutes(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}

	for _, depth := range []int{3, 5, 10} {
		args := buildExecChainArgs(depth)
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Errorf("depth=%d: exec failed: %v (output: %q)", depth, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); got != "es_exit" {
			t.Errorf("depth=%d: output = %q, want %q", depth, got, "es_exit")
		}
	}
}
