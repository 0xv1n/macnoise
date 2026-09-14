//go:build integration && darwin

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

func TestMountedExecutionScenarioRunsFromObservedVolumeAndCleansUp(t *testing.T) {
	sourceDir := filepath.Join(t.TempDir(), "source")
	scenarioPath := filepath.Join("..", "..", "configs", "scenarios", "mounted_execution.yaml")
	var events []module.TelemetryEvent
	report, err := runner.RunScenario(context.Background(), scenarioPath, func(event module.TelemetryEvent) error {
		events = append(events, event)
		return nil
	}, runner.Options{RunID: "mounted-e2e", ScenarioInputs: module.Params{"source_dir": sourceDir}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.Outputs["execution_output"] != module.RedactedValue {
		t.Fatalf("report = %+v", report)
	}

	var imagePath, mountPoint string
	var executed bool
	for _, event := range events {
		switch event.EventType {
		case "volume_image_create":
			imagePath, _ = event.Details["path"].(string)
		case "volume_mount":
			mountPoint, _ = event.Details["mount_point"].(string)
		case "process_exec":
			if event.Subject.Process != nil && mountPoint != "" {
				executed = strings.HasPrefix(event.Subject.Process.Executable, mountPoint+string(filepath.Separator)) &&
					event.Details["output"] == "macnoise mounted payload\n"
			}
		}
	}
	if imagePath == "" || mountPoint == "" || !executed {
		t.Fatalf("connected mounted execution missing: image=%q mount=%q executed=%v events=%+v", imagePath, mountPoint, executed, events)
	}
	for _, path := range []string{sourceDir, imagePath, mountPoint} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("cleanup left %s: %v", path, err)
		}
	}
}
