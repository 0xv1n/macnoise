package endpointsecurity

import (
	"strings"
	"testing"
)

func TestBuildExecChainArgs_Shape(t *testing.T) {
	tests := []struct {
		depth   int
		wantLen int
	}{
		{depth: 1, wantLen: 2},
		{depth: 2, wantLen: 6},
		{depth: 3, wantLen: 10},
		{depth: 5, wantLen: 18},
		{depth: 10, wantLen: 38}, // module's clamp ceiling
	}

	for _, tt := range tests {
		args := buildExecChainArgs(tt.depth, "")
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

func TestBuildExecChainArgs_LinearGrowth(t *testing.T) {
	prevLen := -1
	for depth := 1; depth <= 10; depth++ {
		args := buildExecChainArgs(depth, "")
		if prevLen >= 0 {
			grew := len(args) - prevLen
			if grew != 4 {
				t.Errorf("depth=%d: argv grew by %d elements from depth=%d, want exactly 4 (linear)", depth, grew, depth-1)
			}
		}
		prevLen = len(args)
	}
}

func TestBuildExecChainArgs_NoUserInputInScript(t *testing.T) {
	for _, a := range buildExecChainArgs(5, "") {
		if strings.Contains(a, "'") {
			t.Errorf("argv element %q contains a raw single quote", a)
		}
	}
}

func TestBuildExecChainArgs_RunIDInLeaf(t *testing.T) {
	args := buildExecChainArgs(3, "deadbeef01234567")
	leaf := args[len(args)-1]
	if !strings.Contains(leaf, "deadbeef01234567") {
		t.Errorf("leaf echo arg %q missing run ID", leaf)
	}
	if args[len(args)-2] != "echo" {
		t.Errorf("chain must still end in echo, got %v", args[len(args)-2:])
	}
}
