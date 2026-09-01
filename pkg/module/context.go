package module

import "context"

type runIDKey struct{}

// ContextWithRunID returns a child context carrying the run ID.
func ContextWithRunID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, runIDKey{}, id)
}

// RunIDFromContext returns the run ID from ctx, or "" if none is set.
func RunIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(runIDKey{}).(string)
	return v
}
