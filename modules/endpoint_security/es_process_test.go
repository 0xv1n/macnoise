package endpointsecurity

import (
	"strings"
	"testing"
)

// buildExecChainArgs must produce the fixed 4-element wrapper
// (sh, -c, "$@", sh) once per nesting level, ending in the literal
// innermost command - this is what makes the chain threadable through argv
// without any string-level shell-quote escaping.
func TestBuildExecChainArgs_Shape(t *testing.T) {
	tests := []struct {
		depth   int
		wantLen int
	}{
		{depth: 1, wantLen: 2},  // echo es_exit
		{depth: 2, wantLen: 6},  // + sh -c "$@" sh
		{depth: 3, wantLen: 10}, // + another wrapper
		{depth: 5, wantLen: 18},
		{depth: 10, wantLen: 38}, // this module's own clamp ceiling
	}

	for _, tt := range tests {
		args := buildExecChainArgs(tt.depth)
		if len(args) != tt.wantLen {
			t.Errorf("depth=%d: len(args) = %d, want %d (%v)", tt.depth, len(args), tt.wantLen, args)
		}
		if args[len(args)-2] != "echo" || args[len(args)-1] != "es_exit" {
			t.Errorf("depth=%d: chain must end in echo es_exit, got tail %v", tt.depth, args[len(args)-2:])
		}
		for i := 0; i < tt.depth-1; i++ {
			base := i * 4
			got := args[base : base+4]
			want := []string{"sh", "-c", `"$@"`, "sh"}
			for j := range want {
				if got[j] != want[j] {
					t.Errorf("depth=%d level=%d: wrapper = %v, want %v", tt.depth, i, got, want)
					break
				}
			}
		}
	}
}

// depth grows the argv slice linearly, not exponentially - this is the
// actual property that fixes the bug. The previous implementation built a
// single string via repeated fmt.Sprintf("sh -c '%s'", inner) wrapping,
// which is what grows exponentially and fails outright at depth 10.
func TestBuildExecChainArgs_LinearGrowth(t *testing.T) {
	prevLen := -1
	for depth := 1; depth <= 10; depth++ {
		args := buildExecChainArgs(depth)
		if prevLen >= 0 {
			grew := len(args) - prevLen
			if grew != 4 {
				t.Errorf("depth=%d: argv grew by %d elements from depth=%d, want exactly 4 (linear)", depth, grew, depth-1)
			}
		}
		prevLen = len(args)
	}
}

// The built script must always be the literal `"$@"` idiom, never something
// derived from user input - this module's chain_depth param only controls
// nesting count, never gets interpolated into the script text itself.
func TestBuildExecChainArgs_NoUserInputInScript(t *testing.T) {
	args := buildExecChainArgs(5)
	for _, a := range args {
		if a == "-c" {
			continue
		}
		if strings.Contains(a, "'") {
			t.Errorf("argv element %q contains a raw single quote - the whole point of this construction is that none should ever appear", a)
		}
	}
}
