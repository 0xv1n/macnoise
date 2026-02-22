package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/internal/config"
)

func TestDefaultsReturnsValidConfig(t *testing.T) {
	cfg := config.Defaults()
	if cfg.DefaultFormat == "" {
		t.Error("expected non-empty DefaultFormat")
	}
	if cfg.DefaultTimeout <= 0 {
		t.Error("expected positive DefaultTimeout")
	}
}

func TestLoadEmptyPathReturnsDefaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("unexpected error for empty path: %v", err)
	}
	defaults := config.Defaults()
	if cfg.DefaultFormat != defaults.DefaultFormat {
		t.Errorf("expected default format %q, got %q", defaults.DefaultFormat, cfg.DefaultFormat)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := config.Load("/tmp/macnoise_nonexistent_config_xyz.yaml")
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	defaults := config.Defaults()
	if cfg.DefaultFormat != defaults.DefaultFormat {
		t.Errorf("expected default format, got %q", cfg.DefaultFormat)
	}
}

func TestLoadValidYAML(t *testing.T) {
	content := `
default_format: jsonl
default_timeout: 60
output_file: /tmp/out.jsonl
audit_log: /tmp/audit.jsonl
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultFormat != "jsonl" {
		t.Errorf("expected jsonl, got %q", cfg.DefaultFormat)
	}
	if cfg.DefaultTimeout != 60 {
		t.Errorf("expected timeout 60, got %d", cfg.DefaultTimeout)
	}
	if cfg.OutputFile != "/tmp/out.jsonl" {
		t.Errorf("expected output file, got %q", cfg.OutputFile)
	}
	if cfg.AuditLog != "/tmp/audit.jsonl" {
		t.Errorf("expected audit_log /tmp/audit.jsonl, got %q", cfg.AuditLog)
	}
}

func TestLoadInvalidYAMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{not: valid: yaml: :}"), 0o644)

	_, err := config.Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
