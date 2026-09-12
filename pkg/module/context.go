package module

import (
	"context"
	"fmt"
)

type runIDKey struct{}
type workspaceKey struct{}
type outputSinkKey struct{}

type outputSink func(string, any) error

// ContextWithRunID returns a child context carrying the run ID.
func ContextWithRunID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, runIDKey{}, id)
}

// RunIDFromContext returns the run ID from ctx, or "" if none is set.
func RunIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(runIDKey{}).(string)
	return v
}

// ContextWithWorkspace returns a child context carrying the private scenario
// workspace. Runners, rather than modules, own its lifetime.
func ContextWithWorkspace(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, workspaceKey{}, path)
}

// WorkspaceFromContext returns the private scenario workspace, or an empty
// string for a module invoked outside a scenario.
func WorkspaceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(workspaceKey{}).(string)
	return v
}

// ContextWithOutputSink installs the output collector used by the runner.
// It is public for runner integration; modules should call PublishOutput.
func ContextWithOutputSink(ctx context.Context, sink func(string, any) error) context.Context {
	return context.WithValue(ctx, outputSinkKey{}, outputSink(sink))
}

// PublishOutput publishes one declared output from Generate.
func PublishOutput(ctx context.Context, name string, value any) error {
	sink, _ := ctx.Value(outputSinkKey{}).(outputSink)
	if sink == nil {
		return fmt.Errorf("module output %q has no runner collector", name)
	}
	return sink(name, value)
}
