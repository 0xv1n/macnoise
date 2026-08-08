package runner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

func TestRunSingle_CleanupRunsByDefault(t *testing.T) {
	gen := &mockGen{name: "mock_default_cleanup"}

	if err := runner.RunSingle(context.Background(), gen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{}); err != nil {
		t.Fatalf("RunSingle: %v", err)
	}
	if !gen.cleanedUp {
		t.Error("Cleanup was not called; it must run unless --no-cleanup is given")
	}
}

// The artifact has to survive the run, otherwise there is nothing installed
// for a detection to find and the flag is pointless.
func TestRunSingle_NoCleanupLeavesArtifacts(t *testing.T) {
	gen := &mockGen{name: "mock_no_cleanup"}

	opts := runner.Options{NoCleanup: true}
	if err := runner.RunSingle(context.Background(), gen, module.Params{}, func(module.TelemetryEvent) {}, opts); err != nil {
		t.Fatalf("RunSingle: %v", err)
	}
	if gen.cleanedUp {
		t.Error("Cleanup ran despite NoCleanup being set, so the artifact did not persist")
	}
}

// A skipped cleanup must be distinguishable in the audit log from one that ran
// and succeeded. Recording it as "ok" would claim the host was returned to its
// prior state when persistence is still installed.
func TestRunSingle_NoCleanupIsRecordedAsSkipped(t *testing.T) {
	tests := []struct {
		name      string
		noCleanup bool
		want      string
	}{
		{"cleanup ran", false, "ok"},
		{"cleanup skipped", true, "skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.NewLogger(auditPath, "test")
			if err != nil {
				t.Fatalf("new audit logger: %v", err)
			}

			gen := &mockGen{name: "mock_audit_cleanup"}
			opts := runner.Options{NoCleanup: tt.noCleanup, AuditLog: logger}
			if err := runner.RunSingle(context.Background(), gen, module.Params{}, func(module.TelemetryEvent) {}, opts); err != nil {
				t.Fatalf("RunSingle: %v", err)
			}
			if err := logger.Close(); err != nil {
				t.Fatalf("close audit logger: %v", err)
			}

			got := cleanupResultFromAudit(t, auditPath)
			if got != tt.want {
				t.Errorf("cleanup_result = %q, want %q", got, tt.want)
			}
		})
	}
}

func cleanupResultFromAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not valid JSON: %v", err)
		}
		unmapped, ok := rec["unmapped"].(map[string]any)
		if !ok {
			continue
		}
		if result, ok := unmapped["cleanup_result"].(string); ok {
			return result
		}
	}
	t.Fatal("no lifecycle record with a cleanup_result was written")
	return ""
}
