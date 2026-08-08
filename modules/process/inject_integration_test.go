//go:build integration && darwin

package process

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func runInject(t *testing.T, params module.Params) module.TelemetryEvent {
	t.Helper()
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	if err := (&procInject{}).Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	return events[0]
}

// The default target must be one dyld will actually inject into. The test
// binary itself stands in for macnoise here: both are Go-built and only ad-hoc
// signed, so they exercise the same dyld path.
func TestProcInject_DefaultTargetIsHonouredByDyld(t *testing.T) {
	ev := runInject(t, module.Params{"dylib_path": filepath.Join(t.TempDir(), "absent.dylib")})

	if got := ev.Details["outcome"]; got != "honored" {
		t.Errorf("outcome = %v, want honored; dyld did not act on DYLD_INSERT_LIBRARIES for the default target", got)
	}
	if !ev.Success {
		t.Error("Success = false; dyld aborting the child is the successful injection path, not a failure")
	}
}

// sipEnabled reports whether System Integrity Protection is active.
func sipEnabled(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("csrutil", "status").CombinedOutput()
	if err != nil {
		t.Skipf("cannot determine SIP status: %v: %s", err, out)
	}
	return strings.Contains(strings.ToLower(string(out)), "status: enabled")
}

// Whether a system binary strips DYLD_INSERT_LIBRARIES depends on SIP, so this
// asserts against the host's actual state rather than assuming one. A
// SIP-enabled Mac (any real endpoint) drops the variable, which is why
// /usr/bin/true was a useless default. Some CI images run with SIP off and
// honour it, and asserting "stripped" unconditionally fails there for reasons
// that say nothing about this module.
func TestProcInject_SystemBinaryOutcomeFollowsSIP(t *testing.T) {
	for _, target := range []string{"/usr/bin/true", "/bin/ls"} {
		t.Run(target, func(t *testing.T) {
			ev := runInject(t, module.Params{
				"target":     target,
				"dylib_path": filepath.Join(t.TempDir(), "absent.dylib"),
			})

			want := "honored"
			if sipEnabled(t) {
				want = "stripped"
			}
			if got := ev.Details["outcome"]; got != want {
				t.Errorf("outcome = %v, want %s (SIP enabled: %v)", got, want, sipEnabled(t))
			}
			if ev.Details["target"] != target {
				t.Errorf("target = %v, want %s", ev.Details["target"], target)
			}
		})
	}
}
