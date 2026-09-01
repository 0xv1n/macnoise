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
