package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestFileFindBoundsDepthResultsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.txt"), "a")
	writeTestFile(t, filepath.Join(root, "b.txt"), "b")
	writeTestFile(t, filepath.Join(root, "nested", "c.txt"), "c")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeTestFile(t, outside, "outside")
	if err := os.Symlink(outside, filepath.Join(root, "linked.txt")); err != nil {
		t.Logf("symlink coverage unavailable: %v", err)
	}

	ctx, outputs := outputContext()
	var events []module.TelemetryEvent
	err := (&fileFind{}).Generate(ctx, module.Params{
		"roots":       []string{root},
		"extensions":  []string{".txt"},
		"max_depth":   1,
		"max_results": 2,
		"max_bytes":   0,
	}, func(ev module.TelemetryEvent) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	paths, ok := outputs["paths"].([]string)
	if !ok || len(paths) != 2 {
		t.Fatalf("paths = %#v, want two bounded results", outputs["paths"])
	}
	for _, path := range paths {
		if path == outside || filepath.Base(path) == "linked.txt" || filepath.Base(path) == "c.txt" {
			t.Errorf("discovery escaped its depth/root boundary: %s", path)
		}
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want one per result", len(events))
	}
}

func TestFileFindMissingRootPublishesEmptyPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	ctx, outputs := outputContext()
	var event module.TelemetryEvent
	if err := (&fileFind{}).Generate(ctx, module.Params{
		"roots": []string{root}, "names": []string{}, "extensions": []string{},
		"max_depth": 3, "max_results": 10, "max_bytes": 0,
	}, func(ev module.TelemetryEvent) error { event = ev; return nil }); err != nil {
		t.Fatal(err)
	}
	if paths, ok := outputs["paths"].([]string); !ok || len(paths) != 0 {
		t.Fatalf("paths = %#v, want empty list", outputs["paths"])
	}
	if event.Outcome != module.OutcomeIndeterminate {
		t.Fatalf("outcome = %s, want indeterminate", event.Outcome)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
