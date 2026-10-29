package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionRejectsInvalidConfiguredFormat(t *testing.T) {
	format := globalFormat
	outputPath := globalOutput
	verbose := globalVerbose
	dryRun := globalDryRun
	noCleanup := globalNoCleanup
	configPath := globalConfig
	timeout := globalTimeout
	auditLog := globalAuditLog
	runID := globalRunID
	cfg := loadedConfig
	t.Cleanup(func() {
		globalFormat = format
		globalOutput = outputPath
		globalVerbose = verbose
		globalDryRun = dryRun
		globalNoCleanup = noCleanup
		globalConfig = configPath
		globalTimeout = timeout
		globalAuditLog = auditLog
		globalRunID = runID
		loadedConfig = cfg
	})

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("default_format: csv\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := buildRoot()
	root.SilenceErrors = true
	root.SilenceUsage = true
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"--config", path, "version"})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), `config: default_format "csv"`) {
		t.Fatalf("Execute error = %v, want invalid config format error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("version printed output before config validation: %q", output.String())
	}
}
