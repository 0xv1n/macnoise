//go:build integration && darwin

package process

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Exercises the real xattr/spctl path on macOS: the module must create its
// test file, set and remove the quarantine xattr, and check Gatekeeper status,
// folding the run ID into the tagged file path.
func TestGatekeeperGenerate_FullCycle(t *testing.T) {
	target := filepath.Join(t.TempDir(), "gk_target")

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	p := &procGatekeeper{}
	ctx := module.ContextWithRunID(context.Background(), "gkrun7")
	if err := p.Generate(ctx, module.Params{"target_path": target}, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _ = p.Cleanup() })

	byType := map[string]module.TelemetryEvent{}
	for _, ev := range events {
		byType[ev.EventType] = ev
	}

	for _, et := range []string{"xattr_quarantine_set", "xattr_quarantine_remove", "spctl_status_check"} {
		if _, ok := byType[et]; !ok {
			t.Errorf("missing expected event %q; got %v", et, events)
		}
	}

	set := byType["xattr_quarantine_set"]
	if !set.Success {
		t.Fatalf("quarantine set failed: %s", set.Message)
	}
	if !byType["xattr_quarantine_remove"].Success {
		t.Errorf("quarantine remove failed: %s", byType["xattr_quarantine_remove"].Message)
	}
	// The run ID must ride on the tagged file path.
	if path, _ := set.Details["path"].(string); filepath.Base(path) != "gk_target_gkrun7" {
		t.Errorf("set event path = %q, want base gk_target_gkrun7", path)
	}
}
