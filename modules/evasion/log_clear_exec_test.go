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
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stage, "unrelated")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	histories := []string{
		filepath.Join(t.TempDir(), ".zsh_history"),
		filepath.Join(t.TempDir(), ".bash_history"),
	}
	for _, path := range histories {
		if err := os.WriteFile(path, []byte("secret command\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = module.ContextWithRunID(ctx, "execution")
	g := &evadeLogClear{}
	var events []module.TelemetryEvent
	err := g.Generate(ctx, module.Params{"stage_dir": base, "history_paths": histories}, func(ev module.TelemetryEvent) error {
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
		return nil
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("events = %+v, want timestomp, log erase, and two history operations", events)
	}
	for i, kind := range []string{"file_timestomp", "log_erase_attempt", "history_clear", "history_clear"} {
		if events[i].EventType != kind || events[i].Outcome == module.OutcomeError {
			t.Errorf("event %d = %+v", i, events[i])
		}
	}
	if events[1].Outcome != module.OutcomeDenied || events[1].Error == "" {
		t.Errorf("log erase = %+v, want denied", events[1])
	}
	out, _ := events[1].Details["output"].(string)
	if !strings.Contains(strings.ToLower(out), "root") {
		t.Errorf("log erase output = %q, want a root requirement", out)
	}
	for index, path := range histories {
		if got := events[index+2].Details["path"]; got != path {
			t.Errorf("history path = %v, want %s", got, path)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("history not removed: %s: %v", path, err)
		}
	}
	if err := g.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "keep" {
		t.Fatalf("pre-existing stage content changed: data=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(stage, "timestomp_target")); !os.IsNotExist(err) {
		t.Errorf("owned timestomp target survived cleanup: %v", err)
	}
	for _, path := range histories {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("cleanup restored deleted history %s: %v", path, err)
		}
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
	err := g.Generate(ctx, module.Params{"stage_dir": stage}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		cancel()
		return nil
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
