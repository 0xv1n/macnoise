package main

import (
	"os"
	"path/filepath"
	"testing"
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
