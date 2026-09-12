package module

import (
	"context"
	"testing"
)

func TestRunIDFromContext_RoundTrips(t *testing.T) {
	ctx := ContextWithRunID(context.Background(), "abc123")
	if got := RunIDFromContext(ctx); got != "abc123" {
		t.Errorf("RunIDFromContext = %q, want abc123", got)
	}
}

func TestRunIDFromContext_EmptyWhenUnset(t *testing.T) {
	if got := RunIDFromContext(context.Background()); got != "" {
		t.Errorf("RunIDFromContext on bare context = %q, want empty", got)
	}
}

func TestScenarioContextRoundTripsWorkspaceAndOutputs(t *testing.T) {
	ctx := ContextWithWorkspace(context.Background(), "/private/workspace")
	var name string
	var value any
	ctx = ContextWithOutputSink(ctx, func(gotName string, gotValue any) error {
		name, value = gotName, gotValue
		return nil
	})
	if err := PublishOutput(ctx, "path", "/private/workspace/file"); err != nil {
		t.Fatal(err)
	}
	if WorkspaceFromContext(ctx) != "/private/workspace" || name != "path" || value != "/private/workspace/file" {
		t.Fatalf("workspace = %q, output = %s:%v", WorkspaceFromContext(ctx), name, value)
	}
}
