package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

func TestScenarioPreflightDoesNotCreateOutputFiles(t *testing.T) {
	dir := t.TempDir()
	scenarioPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(scenarioPath, []byte("version: 1\nname: invalid\nsteps:\n  - module: missing_module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "events.jsonl")
	auditPath := filepath.Join(dir, "audit.jsonl")
	reportPath := filepath.Join(dir, "report.json")
	globalOutput = outputPath
	globalAuditLog = auditPath
	t.Cleanup(func() {
		globalOutput = ""
		globalAuditLog = ""
	})

	cmd := buildScenario()
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, []string{scenarioPath}); err == nil {
		t.Fatal("invalid scenario passed preflight")
	}
	for _, path := range []string{outputPath, auditPath, reportPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("preflight failure created %s", path)
		}
	}
}

func TestFileFlowScenarioConnectsRealArtifactsAndCleansUp(t *testing.T) {
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar is required for the stock file flow")
	}
	dir := t.TempDir()
	baseDir := filepath.Join(dir, "source")
	archivePath := filepath.Join(dir, "flow.tar.gz")
	copyDir := filepath.Join(dir, "copy")
	scenarioPath := filepath.Join("..", "..", "configs", "scenarios", "file_flow.yaml")
	var events []module.TelemetryEvent
	report, err := runner.RunScenario(context.Background(), scenarioPath, func(event module.TelemetryEvent) error {
		events = append(events, event)
		return nil
	}, runner.Options{ScenarioInputs: module.Params{"base_dir": baseDir, "archive_path": archivePath, "copy_dir": copyDir}})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.Outputs["archive"] != archivePath {
		t.Fatalf("report = %+v", report)
	}

	artifactPath := filepath.Join(baseDir, "artifact.txt")
	var sawCreate, sawModify, sawDiscover, sawRead, sawCopy, sawArchive bool
	for _, event := range events {
		switch event.EventType {
		case "file_create":
			sawCreate = event.Subject.File != nil && event.Subject.File.Path == artifactPath
		case "file_modify":
			sawModify = event.Subject.File != nil && event.Subject.File.Path == artifactPath
		case "file_discover":
			sawDiscover = event.Subject.File != nil && event.Subject.File.Path == artifactPath
		case "file_read":
			if event.Subject.File != nil && event.Subject.File.Path == artifactPath {
				sawRead = true
			}
		case "file_copy":
			sawCopy = event.Details["source_path"] == artifactPath
		case "archive_create":
			sawArchive = event.Details["source_path"] == artifactPath && event.Subject.File != nil && event.Subject.File.Path == archivePath
		}
	}
	if !sawCreate || !sawModify || !sawDiscover || !sawRead || !sawCopy || !sawArchive {
		t.Fatalf("connected events missing: create=%v modify=%v discover=%v read=%v copy=%v archive=%v events=%+v",
			sawCreate, sawModify, sawDiscover, sawRead, sawCopy, sawArchive, events)
	}
	for _, path := range []string{artifactPath, baseDir, copyDir, archivePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("cleanup left %s: %v", path, err)
		}
	}
}

func TestScenarioModuleValidationRunsBeforeWorkspaceOrMutation(t *testing.T) {
	dir := t.TempDir()
	baseDir := filepath.Join(dir, "must-not-exist")
	scenarioPath := filepath.Join(dir, "invalid-file.yaml")
	body := "version: 1\nname: invalid file path\nsteps:\n" +
		"  - module: file_create\n    params:\n      base_dir: " + filepath.ToSlash(baseDir) + "\n      filename: ../escape.txt\n"
	if err := os.WriteFile(scenarioPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := runner.RunScenario(context.Background(), scenarioPath, func(module.TelemetryEvent) error { return nil }, runner.Options{})
	if err == nil {
		t.Fatal("invalid module-specific parameter passed preflight")
	}
	if report.Workspace != "" {
		t.Fatalf("preflight created workspace %q", report.Workspace)
	}
	if _, err := os.Stat(baseDir); !os.IsNotExist(err) {
		t.Fatalf("preflight created %s: %v", baseDir, err)
	}
}
