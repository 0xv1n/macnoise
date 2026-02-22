package runner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

type mockGen struct {
	name        string
	prereqErr   error
	generateErr error
	cleanupErr  error
	events      []module.TelemetryEvent
	dryRunLines []string
	cleanedUp   bool
}

func (m *mockGen) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: m.name, Category: "test"}
}
func (m *mockGen) ParamSpecs() []module.ParamSpec { return nil }
func (m *mockGen) CheckPrereqs() error             { return m.prereqErr }
func (m *mockGen) Generate(_ context.Context, _ module.Params, emit module.EventEmitter) error {
	for _, ev := range m.events {
		emit(ev)
	}
	return m.generateErr
}
func (m *mockGen) DryRun(_ module.Params) []string { return m.dryRunLines }
func (m *mockGen) Cleanup() error {
	m.cleanedUp = true
	return m.cleanupErr
}

func TestRunSingleSuccess(t *testing.T) {
	ev := module.TelemetryEvent{Module: "mock", Success: true, Message: "ok"}
	gen := &mockGen{
		name:        "mock_success",
		events:      []module.TelemetryEvent{ev},
		dryRunLines: []string{"do something"},
	}

	var received []module.TelemetryEvent
	emit := func(e module.TelemetryEvent) { received = append(received, e) }

	err := runner.RunSingle(context.Background(), gen, module.Params{}, emit, runner.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(received) != 1 {
		t.Errorf("expected 1 event, got %d", len(received))
	}
	if !gen.cleanedUp {
		t.Error("expected Cleanup to be called")
	}
}

func TestRunSinglePrereqFails(t *testing.T) {
	gen := &mockGen{
		name:      "mock_prereq_fail",
		prereqErr: errors.New("not root"),
	}
	err := runner.RunSingle(context.Background(), gen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{})
	if err == nil {
		t.Error("expected error when prereqs fail")
	}
}

func TestRunSingleDryRun(t *testing.T) {
	gen := &mockGen{
		name:        "mock_dryrun",
		dryRunLines: []string{"action one", "action two"},
		generateErr: errors.New("should not run"),
	}
	err := runner.RunSingle(context.Background(), gen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}
	if gen.cleanedUp {
		t.Error("Cleanup should not be called during dry-run")
	}
}

func TestRunSingleTimeout(t *testing.T) {
	gen := &mockGen{name: "mock_timeout"}
	gen.events = nil
	slowGen := &slowMockGen{name: "mock_slow", delay: 2 * time.Second}

	err := runner.RunSingle(context.Background(), slowGen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Error("expected timeout error")
	}
	_ = gen
}

func TestRunManyCollectsErrors(t *testing.T) {
	gens := []module.Generator{
		&mockGen{name: "mock_ok"},
		&mockGen{name: "mock_fail", generateErr: errors.New("boom")},
	}
	err := runner.RunMany(context.Background(), gens, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{})
	if err == nil {
		t.Error("expected combined error")
	}
}

type slowMockGen struct {
	name  string
	delay time.Duration
}

func (s *slowMockGen) Info() module.ModuleInfo { return module.ModuleInfo{Name: s.name} }
func (s *slowMockGen) ParamSpecs() []module.ParamSpec { return nil }
func (s *slowMockGen) CheckPrereqs() error { return nil }
func (s *slowMockGen) Generate(ctx context.Context, _ module.Params, _ module.EventEmitter) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.delay):
		return nil
	}
}
func (s *slowMockGen) DryRun(_ module.Params) []string { return nil }
func (s *slowMockGen) Cleanup() error { return nil }
