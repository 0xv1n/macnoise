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

	ev := timestomp(info, target)
	if ev.EventType != "file_timestomp" {
		t.Fatalf("event type = %q, want file_timestomp", ev.EventType)
	}
	if !ev.Success {
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
	ev := timestomp(info, filepath.Join(t.TempDir(), "no", "such", "dir", "file"))
	if ev.Success {
		t.Error("expected failure for nonexistent parent dir")
	}
}

func TestClearHistory_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	info := (&evadeLogClear{}).Info()

	ev := clearHistory(info, dir)
	if ev.EventType != "history_clear" {
		t.Fatalf("event type = %q, want history_clear", ev.EventType)
	}
	if !ev.Success {
		t.Fatalf("history clear reported failure: %s", ev.Message)
	}

	histFile := filepath.Join(dir, ".zsh_history")
	if _, err := os.Stat(histFile); !os.IsNotExist(err) {
		t.Error("mock history file still exists after clear")
	}
}

func TestDryRunListsAllTechniques(t *testing.T) {
	mod := &evadeLogClear{}
	steps := mod.DryRun(module.Params{})
	if len(steps) != 4 {
		t.Fatalf("dry run listed %d steps, want 4", len(steps))
	}
}

func TestCleanupRemovesStagingDir(t *testing.T) {
	dir := t.TempDir()
	stageDir := filepath.Join(dir, "evasion_stage")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "artifact"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	mod := &evadeLogClear{stageDir: stageDir}
	if err := mod.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Error("staging dir still exists after cleanup")
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
