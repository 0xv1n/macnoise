//go:build !windows

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Use real POSIX sh, as in spawn_exec_test.go; Windows shell argument
// handling does not represent the module's macOS execution environment.
func TestDiscoveryGenerate_Commands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "executed")
	commands := []string{
		`printf 'stdout\n'; printf 'stderr\n' >&2`,
		`printf 'failed\n' >&2; exit 7`,
		fmt.Sprintf(`printf 'continued\n' | tee '%s'`, marker),
	}
	var events []module.TelemetryEvent
	p := &procDiscovery{}
	err := p.Generate(ctx, module.Params{"commands": " , " + strings.Join(commands, " , , ") + ", "}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != len(commands) {
		t.Fatalf("got %d events, want %d: %+v", len(events), len(commands), events)
	}
	for i, ev := range events {
		if ev.Module != "proc_discovery" || ev.EventType != "system_discovery" || !ev.Success {
			t.Errorf("event %d: %+v", i, ev)
		}
		if ev.Details["command"] != commands[i] {
			t.Errorf("command %d = %q, want %q", i, ev.Details["command"], commands[i])
		}
	}
	for i, want := range []string{"stdout\nstderr\n", "failed\n", "continued\n"} {
		if events[i].Details["output"] != want {
			t.Errorf("output %d = %q, want %q", i, events[i].Details["output"], want)
		}
	}
	if events[1].Details["error"] != "exit status 7" {
		t.Errorf("failed command error = %v", events[1].Details["error"])
	}
	for _, i := range []int{0, 2} {
		if _, ok := events[i].Details["error"]; ok {
			t.Errorf("successful command %d has error: %+v", i, events[i])
		}
	}
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	// Discovery cleanup is a no-op, including for effects of custom commands.
	if data, err := os.ReadFile(marker); err != nil || string(data) != "continued\n" {
		t.Fatalf("later command did not write marker: %q, %v", data, err)
	}
}

func TestDiscoveryGenerate_CanceledBeforeCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	marker := filepath.Join(t.TempDir(), "unexpected")
	err := (&procDiscovery{}).Generate(ctx, module.Params{"commands": fmt.Sprintf("touch '%s'", marker)}, func(ev module.TelemetryEvent) {
		t.Errorf("unexpected event: %+v", ev)
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("canceled command ran: %v", err)
	}
}

func TestDiscoveryGenerate_CanceledBetweenCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	marker := filepath.Join(t.TempDir(), "unexpected")
	var events []module.TelemetryEvent
	err := (&procDiscovery{}).Generate(ctx, module.Params{"commands": fmt.Sprintf("printf first,touch '%s'", marker)}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate = %v, want context.Canceled", err)
	}
	if len(events) != 1 || events[0].Details["output"] != "first" {
		t.Fatalf("expected only the first command result: %+v", events)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command after cancellation ran: %v", err)
	}
}

func TestDiscoveryGenerate_CanceledDuringCommand(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				want = context.DeadlineExceeded
			}
			defer cancel()
			marker := filepath.Join(t.TempDir(), "started")
			var events []module.TelemetryEvent
			done := make(chan error, 1)
			go func() {
				// exec leaves no descendant holding the output pipe after cancellation.
				done <- (&procDiscovery{}).Generate(ctx, module.Params{"commands": fmt.Sprintf("printf started > '%s'; exec sleep 10", marker)}, func(ev module.TelemetryEvent) {
					events = append(events, ev)
				})
			}()
			// Always reap the command before inspecting events or removing its directory.
			defer func() { cancel(); <-done }()
			startLimit := time.After(5 * time.Second)
			for {
				if data, err := os.ReadFile(marker); err == nil && string(data) == "started" {
					break
				}
				select {
				case <-startLimit:
					t.Fatal("command did not start")
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				close(done)
				if !errors.Is(err, want) {
					t.Errorf("Generate = %v, want %v", err, want)
				}
				if len(events) != 0 {
					t.Errorf("canceled command emitted completed results: %+v", events)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Generate did not stop promptly")
			}
		})
	}
}
