package runner_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/internal/audit"
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
func (m *mockGen) CheckPrereqs() error            { return m.prereqErr }
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
	slowGen := &slowMockGen{name: "mock_slow", delay: 2 * time.Second}

	err := runner.RunSingle(context.Background(), slowGen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Error("expected timeout error")
	}
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
	name      string
	delay     time.Duration
	cleanedUp bool
}

func (s *slowMockGen) Info() module.ModuleInfo        { return module.ModuleInfo{Name: s.name} }
func (s *slowMockGen) ParamSpecs() []module.ParamSpec { return nil }
func (s *slowMockGen) CheckPrereqs() error            { return nil }
func (s *slowMockGen) Generate(ctx context.Context, _ module.Params, _ module.EventEmitter) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.delay):
		return nil
	}
}
func (s *slowMockGen) DryRun(_ module.Params) []string { return nil }
func (s *slowMockGen) Cleanup() error {
	s.cleanedUp = true
	return nil
}

// Cleanup must run when an operator interrupts a run, otherwise modules that
// install persistence leave artifacts behind on Ctrl-C.
func TestRunSingleCleansUpOnCancel(t *testing.T) {
	gen := &slowMockGen{name: "mock_cancel", delay: 10 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	err := runner.RunSingle(ctx, gen, module.Params{}, func(module.TelemetryEvent) {}, runner.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if !gen.cleanedUp {
		t.Error("expected Cleanup to run after cancellation")
	}
}

// countingGen records how many times Generate was invoked and can trigger a
// side-effect (used here to cancel the scenario context mid-run).
type countingGen struct {
	name   string
	calls  int
	onCall func()
}

func (c *countingGen) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: c.name, Category: "test"}
}
func (c *countingGen) ParamSpecs() []module.ParamSpec { return nil }
func (c *countingGen) CheckPrereqs() error            { return nil }
func (c *countingGen) Generate(_ context.Context, _ module.Params, _ module.EventEmitter) error {
	c.calls++
	if c.onCall != nil {
		c.onCall()
	}
	return nil
}
func (c *countingGen) DryRun(_ module.Params) []string { return nil }
func (c *countingGen) Cleanup() error                  { return nil }

// writeScenario builds a temp scenario file invoking moduleName stepCount times.
func writeScenario(t *testing.T, moduleName string, stepCount int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	body := "name: cancel test\nsteps:\n" +
		strings.Repeat("  - module: "+moduleName+"\n", stepCount)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	return path
}

// An interrupted scenario must stop at the step it reached rather than
// fast-failing through every remaining step.
func TestRunScenarioStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gen := &countingGen{name: "mock_scenario_step", onCall: cancel}
	module.Register(gen)

	path := writeScenario(t, gen.name, 4)

	err := runner.RunScenario(ctx, path, func(module.TelemetryEvent) {}, runner.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if gen.calls != 1 {
		t.Errorf("expected scenario to stop after 1 step, ran %d", gen.calls)
	}
}

// Interrupting a scenario must still produce a scenario-level audit record, so
// an operator can see how far the run got before it was cut short.
func TestRunScenarioAuditsInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gen := &countingGen{name: "mock_audited_step", onCall: cancel}
	module.Register(gen)

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewLogger(auditPath, "test")
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	path := writeScenario(t, gen.name, 5)
	runErr := runner.RunScenario(ctx, path, func(module.TelemetryEvent) {}, runner.Options{AuditLog: logger})
	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", runErr)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close audit logger: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	var scenarioRec map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("audit line is not valid JSON: %v", err)
		}
		if unmapped, ok := rec["unmapped"].(map[string]any); ok {
			if _, isScenario := unmapped["total_steps"]; isScenario {
				scenarioRec = rec
			}
		}
	}

	if scenarioRec == nil {
		t.Fatal("no scenario-level audit record was written for the interrupted run")
	}

	unmapped := scenarioRec["unmapped"].(map[string]any)
	if got := unmapped["steps_passed"]; got != float64(1) {
		t.Errorf("steps_passed = %v, want 1", got)
	}
	if got := unmapped["total_steps"]; got != float64(5) {
		t.Errorf("total_steps = %v, want 5", got)
	}
	if msg, _ := unmapped["scenario_error"].(string); !strings.Contains(msg, "interrupted") {
		t.Errorf("scenario_error = %q, want it to mention the interrupt", msg)
	}
	if got := scenarioRec["status_id"]; got != float64(2) {
		t.Errorf("status_id = %v, want 2 (Failure) for an interrupted scenario", got)
	}
}
