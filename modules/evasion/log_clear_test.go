package evasion

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestTimestomp_ChangesMtime(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ts_target")
	info := (&evadeLogClear{}).Info()

	ev, _, err := timestomp(info, target)
	if err != nil {
		t.Fatalf("timestomp: %v", err)
	}
	if ev.EventType != "file_timestomp" {
		t.Fatalf("event type = %q, want file_timestomp", ev.EventType)
	}
	if ev.Outcome != module.OutcomeExecuted {
		t.Fatalf("timestomp reported failure: %s", ev.Message)
	}

	stat, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if !stat.ModTime().Equal(want) {
		t.Errorf("mtime = %v, want %v", stat.ModTime(), want)
	}
}

func TestTimestomp_BadPath(t *testing.T) {
	info := (&evadeLogClear{}).Info()
	ev, _, _ := timestomp(info, filepath.Join(t.TempDir(), "no", "such", "dir", "file"))
	if ev.Outcome != module.OutcomeError {
		t.Error("expected failure for nonexistent parent dir")
	}
}

func TestTimestomp_PreservesExistingTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "ts_target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	ev, _, _ := timestomp((&evadeLogClear{}).Info(), target)
	if ev.Outcome != module.OutcomeError {
		t.Fatalf("timestomp outcome = %q, want error", ev.Outcome)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep" {
		t.Fatalf("existing target changed: data=%q err=%v", data, err)
	}
}

func TestClearHistory_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	info := (&evadeLogClear{}).Info()
	histFile := filepath.Join(dir, ".zsh_history")
	if err := os.WriteFile(histFile, []byte("secret command\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ev, err := clearHistory(info, histFile)
	if err != nil {
		t.Fatalf("clearHistory: %v", err)
	}
	if ev.EventType != "history_clear" {
		t.Fatalf("event type = %q, want history_clear", ev.EventType)
	}
	if ev.Outcome != module.OutcomeExecuted {
		t.Fatalf("history clear reported failure: %s", ev.Message)
	}

	if _, err := os.Stat(histFile); !os.IsNotExist(err) {
		t.Error("mock history file still exists after clear")
	}
}

func TestClearHistory_MissingFileIsIndeterminate(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zsh_history")
	ev, err := clearHistory((&evadeLogClear{}).Info(), path)
	if err != nil {
		t.Fatalf("clearHistory: %v", err)
	}
	if ev.Outcome != module.OutcomeIndeterminate {
		t.Fatalf("history clear outcome = %q, want indeterminate", ev.Outcome)
	}
}

func TestDryRunListsAllTechniques(t *testing.T) {
	mod := &evadeLogClear{}
	steps := mod.DryRun(module.Params{})
	if len(steps) != 5 {
		t.Fatalf("dry run listed %d steps, want 5", len(steps))
	}
}

func TestEvadeLogClearInfo(t *testing.T) {
	info := (&evadeLogClear{}).Info()
	if info.Name != "evade_log_clear" {
		t.Errorf("name = %q, want evade_log_clear", info.Name)
	}
	if len(info.MITRE) != 3 {
		t.Errorf("expected 3 MITRE entries, got %d", len(info.MITRE))
	}
}
