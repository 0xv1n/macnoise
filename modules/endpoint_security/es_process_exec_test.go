//go:build !windows

package endpointsecurity

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
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

func TestESProcessGenerate_Chains(t *testing.T) {
	// Record each wrapper invocation, then delegate to the real POSIX shell.
	// This checks actual nesting as well as the depth reported in the event.
	dir := t.TempDir()
	trace := filepath.Join(dir, "shells")
	if err := os.WriteFile(filepath.Join(dir, "sh"), []byte("#!/bin/sh\nprintf 'sh\\n' >> \"$MACNOISE_TEST_TRACE\"\nexec /bin/sh \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MACNOISE_TEST_TRACE", trace)
	for _, tt := range []struct {
		name, depth, runID string
		wantDepth          int
	}{
		{"default", "", "abc123", 3},
		{"invalid_defaults", "invalid", "abc123", 3},
		{"leaf", "1", "", 1},
		{"nested", "5", "abc123", 5},
		{"ceiling", "10", "abc123", 10},
		{"clamped", "100", "abc123", 10},
		{"literal_run_id", "3", "id 'quoted' $(printf injected); value", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(trace, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = module.ContextWithRunID(ctx, tt.runID)
			var events []module.TelemetryEvent
			p := &esProcess{}
			if err := p.Generate(ctx, module.Params{"chain_depth": tt.depth}, func(ev module.TelemetryEvent) {
				events = append(events, ev)
			}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("events = %+v, want one", events)
			}
			ev := events[0]
			if ev.Module != "es_process" || ev.EventType != "es_exec_chain" || !ev.Success || ev.Error != "" || ev.ResolvedOutcome() != module.OutcomeExecuted {
				t.Errorf("unexpected event: %+v", ev)
			}
			wantOutput := "es_exit"
			if tt.runID != "" {
				wantOutput += "_" + tt.runID
			}
			if ev.Details["output"] != wantOutput+"\n" || ev.Details["chain_depth"] != tt.wantDepth {
				t.Errorf("details = %+v, want depth %d and output %q", ev.Details, tt.wantDepth, wantOutput+"\n")
			}
			data, err := os.ReadFile(trace)
			if err != nil || string(data) != strings.Repeat("sh\n", tt.wantDepth-1) {
				t.Errorf("shell trace = %q, %v; want %d wrappers", data, err, tt.wantDepth-1)
			}
			if err := p.Cleanup(context.Background()); err != nil {
				t.Fatalf("Cleanup: %v", err)
			}
		})
	}
}

func TestESProcessGenerate_MissingShell(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var events []module.TelemetryEvent
	err := (&esProcess{}).Generate(context.Background(), nil, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	})
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("Generate = %v, want missing executable", err)
	}
	if len(events) != 1 || events[0].Success || events[0].Error != err.Error() || events[0].ResolvedOutcome() != module.OutcomeError {
		t.Fatalf("expected one failed event: %+v", events)
	}
}

func TestESProcessGenerate_CanceledBeforeExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []module.TelemetryEvent
	err := (&esProcess{}).Generate(ctx, nil, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
	if len(events) != 1 || events[0].Success || events[0].Error != err.Error() || events[0].ResolvedOutcome() != module.OutcomeError {
		t.Fatalf("expected one canceled event: %+v", events)
	}
}
