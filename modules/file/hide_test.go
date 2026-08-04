//go:build integration && darwin

package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileHide_GenerateAndCleanup(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "hide")
	f := &fileHide{}
	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }

	params := module.Params{"work_dir": workDir}
	if err := f.Generate(context.Background(), params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := os.Stat(filepath.Join(workDir, "visible_file.txt")); err != nil {
		t.Errorf("chflags target not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, ".macnoise_hidden")); err != nil {
		t.Errorf("dotfile not created: %v", err)
	}

	var sawChflags, sawDotfile bool
	for _, ev := range events {
		switch ev.EventType {
		case "file_hide_chflags":
			sawChflags = sawChflags || ev.Success
		case "file_hide_dotfile":
			sawDotfile = sawDotfile || ev.Success
		}
	}
	if !sawChflags {
		t.Error("expected a successful file_hide_chflags event")
	}
	if !sawDotfile {
		t.Error("expected a successful file_hide_dotfile event")
	}

	if err := f.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Errorf("expected work_dir to be removed after Cleanup, stat err = %v", err)
	}
}
