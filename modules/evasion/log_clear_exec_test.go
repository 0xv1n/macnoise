//go:build integration && darwin

package evasion

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestLogClearGenerate_RealExecution(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("log erase must never execute as root in tests")
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	base := filepath.Join(t.TempDir(), "stage")
	stage := base + "_execution"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = module.ContextWithRunID(ctx, "execution")
	g := &evadeLogClear{}
	var events []module.TelemetryEvent
	err := g.Generate(ctx, module.Params{"stage_dir": base}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
		if ev.EventType == "file_timestomp" {
			stat, err := os.Stat(filepath.Join(stage, "timestomp_target"))
			if err != nil {
				t.Fatalf("timestomp target: %v", err)
			}
			if want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC); !stat.ModTime().Equal(want) {
				t.Errorf("mtime = %v, want %v", stat.ModTime(), want)
			}
		}
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %+v, want three operations", events)
	}
	for i, kind := range []string{"file_timestomp", "log_erase_attempt", "history_clear"} {
		if events[i].EventType != kind || !events[i].Success {
			t.Errorf("event %d = %+v", i, events[i])
		}
	}
	if events[1].ResolvedOutcome() != module.OutcomeDenied || events[1].Error == "" {
		t.Errorf("log erase = %+v, want denied", events[1])
	}
	out, _ := events[1].Details["output"].(string)
	if !strings.Contains(strings.ToLower(out), "root") {
		t.Errorf("log erase output = %q, want a root requirement", out)
	}
	if got := events[2].Details["path"]; got != filepath.Join(stage, ".zsh_history") {
		t.Errorf("history path = %v", got)
	}
	if _, err := os.Stat(filepath.Join(stage, ".zsh_history")); !os.IsNotExist(err) {
		t.Errorf("history not removed: %v", err)
	}
	if err := g.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("stage not removed: %v", err)
	}
}

func TestLogClearGenerate_CancelBetweenOperations(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("log erase must never execute as root in tests")
	}
	g := &evadeLogClear{}
	stage := filepath.Join(t.TempDir(), "stage")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []module.TelemetryEvent
	err := g.Generate(ctx, module.Params{"stage_dir": stage}, func(ev module.TelemetryEvent) {
		events = append(events, ev)
		cancel()
	})
	if !errors.Is(err, context.Canceled) || len(events) != 1 || events[0].EventType != "file_timestomp" {
		t.Fatalf("Generate = %v, events = %+v", err, events)
	}
	if err := g.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("stage not removed: %v", err)
	}
}
