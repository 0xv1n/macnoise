//go:build integration && darwin

package evasion

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// Runs the real copy-and-exec on macOS: a copy of /usr/bin/true executed under
// a system process name must emit a masquerade_copy and a masquerade_exec, with
// the run ID folded into the staged path.
func TestMasqueradeGenerate_CopiesAndExecutes(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "mq")

	var events []module.TelemetryEvent
	emit := func(ev module.TelemetryEvent) { events = append(events, ev) }
	e := &evadeMasquerade{}
	ctx := module.ContextWithRunID(context.Background(), "mqrun5")
	params := module.Params{"stage_dir": stage, "masquerade_name": "com.apple.WindowServer"}
	if err := e.Generate(ctx, params, emit); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _ = e.Cleanup(context.Background()) })

	if len(events) != 2 {
		t.Fatalf("emitted %d events, want 2: %+v", len(events), events)
	}
	if events[0].EventType != "masquerade_copy" || events[1].EventType != "masquerade_exec" {
		t.Fatalf("event types = %q,%q; want masquerade_copy,masquerade_exec", events[0].EventType, events[1].EventType)
	}
	if !events[0].Success {
		t.Fatalf("copy failed: %s", events[0].Message)
	}
	// A copy of /usr/bin/true exits 0, so the masqueraded exec should succeed.
	if !events[1].Success {
		t.Errorf("masqueraded exec failed: %s", events[1].Message)
	}
	if events[1].Details["masqueraded_as"] != "com.apple.WindowServer" {
		t.Errorf("exec masqueraded_as = %v, want com.apple.WindowServer", events[1].Details["masqueraded_as"])
	}
	// The run ID must ride on the staged path.
	if path, _ := events[0].Details["path"].(string); !filepath.IsAbs(path) || filepath.Base(filepath.Dir(path)) != "mq_mqrun5" {
		t.Errorf("staged path %q should sit under the run-ID-tagged stage dir mq_mqrun5", path)
	}
}
