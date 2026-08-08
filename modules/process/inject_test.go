package process

import "testing"

// A protected target has DYLD_INSERT_LIBRARIES stripped before dyld runs, and
// the process then exits cleanly with no diagnostic. Silence therefore means
// the injection never happened, which is the opposite of what the old module
// reported when it called every spawn a success.
func TestClassifyInjection(t *testing.T) {
	const dyldComplaint = `dyld[72146]: terminating because inserted dylib '/tmp/x.dylib' could not be loaded: tried: '/tmp/x.dylib' (no such file)`

	tests := []struct {
		name        string
		dylibExists bool
		stderr      string
		want        injectOutcome
	}{
		{
			name:        "dyld complaint proves the variable survived",
			dylibExists: false,
			stderr:      dyldComplaint,
			want:        injectHonored,
		},
		{
			name:        "silence with an absent dylib proves it was stripped",
			dylibExists: false,
			stderr:      "",
			want:        injectStripped,
		},
		{
			name:        "unrelated stderr is still a stripped result",
			dylibExists: false,
			stderr:      "some unrelated program output\n",
			want:        injectStripped,
		},
		{
			name:        "an existing dylib that loads cleanly is not guessed at",
			dylibExists: true,
			stderr:      "",
			want:        injectIndeterminate,
		},
		{
			name:        "an existing dylib dyld rejected is still honoured",
			dylibExists: true,
			stderr:      dyldComplaint,
			want:        injectHonored,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInjection(tt.dylibExists, tt.stderr); got != tt.want {
				t.Errorf("classifyInjection(%v, %q) = %q, want %q", tt.dylibExists, tt.stderr, got, tt.want)
			}
		})
	}
}
