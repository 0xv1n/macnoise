package runner_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

type mockGen struct {
	name          string
	category      module.Category
	prereqErr     error
	generateErr   error
	cleanupErr    error
	events        []module.TelemetryEvent
	dryRunLines   []string
	onGenerate    func()
	cleanedUp     bool
	cleanupRunID  string
	paramSpecs    []module.ParamSpec
	params        module.Params
	prereqCalls   int
	dryRunCalls   int
	generateCalls int
}

func discardEvent(module.TelemetryEvent) error { return nil }

func (m *mockGen) Info() module.ModuleInfo {
	category := m.category
	if category == "" {
		category = "test"
	}
	return module.ModuleInfo{Name: m.name, Category: category}
}
func (m *mockGen) ParamSpecs() []module.ParamSpec { return m.paramSpecs }
func (m *mockGen) CheckPrereqs(ctx context.Context, params module.Params) error {
	m.prereqCalls++
	return m.prereqErr
}
func (m *mockGen) Generate(_ context.Context, params module.Params, emit module.EventEmitter) error {
	m.generateCalls++
	m.params = params
	if m.onGenerate != nil {
		m.onGenerate()
	}
	for _, ev := range m.events {
		if err := emit(ev); err != nil {
			return errors.Join(m.generateErr, err)
		}
	}
	return m.generateErr
}
func (m *mockGen) DryRun(params module.Params) []string {
	m.dryRunCalls++
	m.params = params
	return m.dryRunLines
}
func (m *mockGen) Cleanup(ctx context.Context) error {
	m.cleanedUp = true
	m.cleanupRunID = module.RunIDFromContext(ctx)
	return m.cleanupErr
}

func TestRunSingleRejectsInvalidParamsBeforePreviewOrExecution(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry_run_%v", dryRun), func(t *testing.T) {
			gen := &mockGen{
				name:       "typed",
				paramSpecs: []module.ParamSpec{{Name: "count", Type: module.ParamInteger}},
			}

			err := runner.RunSingle(context.Background(), gen, module.Params{"count": "many"}, discardEvent, runner.Options{DryRun: dryRun})
			if err == nil || !strings.Contains(err.Error(), `parameter "count" must be an integer`) {
				t.Fatalf("RunSingle error = %v", err)
			}
			if gen.prereqCalls != 0 || gen.dryRunCalls != 0 || gen.generateCalls != 0 || gen.cleanedUp {
				t.Fatalf("invalid input reached lifecycle: %+v", gen)
			}
		})
	}
}

func TestRunSingleUsesSameNormalizationForPreviewAndExecution(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry_run_%v", dryRun), func(t *testing.T) {
			gen := &mockGen{
				name:       "typed",
				paramSpecs: []module.ParamSpec{{Name: "count", Type: module.ParamInteger, Default: 3}},
			}

			if err := runner.RunSingle(context.Background(), gen, module.Params{}, discardEvent, runner.Options{DryRun: dryRun}); err != nil {
				t.Fatal(err)
			}
			if got := gen.params.Int("count", 0); got != 3 {
				t.Fatalf("normalized count = %d, want 3", got)
			}
		})
	}
}

func TestRunSingleSuccess(t *testing.T) {
	ev := module.TelemetryEvent{Module: "mock", Outcome: module.OutcomeExecuted, Subject: module.Resource("test", "mock", ""), Message: "ok"}
	gen := &mockGen{
		name:        "mock_success",
		events:      []module.TelemetryEvent{ev},
		dryRunLines: []string{"do something"},
	}

	var received []module.TelemetryEvent
	emit := func(e module.TelemetryEvent) error {
		received = append(received, e)
		return nil
	}

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

type ignoresEmitterFailureGen struct {
	mockGen
}

func (g *ignoresEmitterFailureGen) Generate(_ context.Context, _ module.Params, emit module.EventEmitter) error {
	g.generateCalls++
	_ = emit(module.TelemetryEvent{
		Outcome: module.OutcomeExecuted,
		Subject: module.Resource("test", "event", ""),
	})
	return nil
}

func TestRunSingleReturnsIgnoredEmitterFailure(t *testing.T) {
	want := errors.New("telemetry write failed")
	gen := &ignoresEmitterFailureGen{mockGen: mockGen{name: "writer_failure"}}

	err := runner.RunSingle(context.Background(), gen, nil, func(module.TelemetryEvent) error {
		return want
	}, runner.Options{})
	if !errors.Is(err, want) {
		t.Fatalf("RunSingle = %v, want telemetry write failure", err)
	}
	if !gen.cleanedUp {
		t.Fatal("cleanup did not run after telemetry write failure")
	}
}

func TestRunSingleRedactsSensitiveAuditParams(t *testing.T) {
	const secret = "correct-horse-battery-staple"
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewLogger(auditPath, "test", "run")
	if err != nil {
		t.Fatal(err)
	}
	gen := &mockGen{
		name: "sensitive_params",
		paramSpecs: []module.ParamSpec{
			{Name: "password", Type: module.ParamString, Sensitive: true},
		},
	}

	if err := runner.RunSingle(context.Background(), gen, module.Params{"password": secret}, discardEvent, runner.Options{AuditLog: logger}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("audit log contains sensitive parameter value")
	}
	if !strings.Contains(string(data), module.RedactedValue) {
		t.Fatal("audit log does not contain redaction marker")
	}
}

func TestRunSingleReturnsCleanupError(t *testing.T) {
	want := errors.New("cleanup failed")
	gen := &mockGen{name: "cleanup_error", cleanupErr: want}
	err := runner.RunSingle(context.Background(), gen, nil, discardEvent, runner.Options{})
	if !errors.Is(err, want) {
		t.Fatalf("RunSingle = %v, want cleanup failure", err)
	}
}

func TestRunSingleJoinsGenerateAndCleanupErrors(t *testing.T) {
	generateErr := errors.New("generation failed")
	cleanupErr := errors.New("cleanup failed")
	gen := &mockGen{name: "joined_errors", generateErr: generateErr, cleanupErr: cleanupErr}
	err := runner.RunSingle(context.Background(), gen, nil, discardEvent, runner.Options{})
	if !errors.Is(err, generateErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("RunSingle = %v, want both generation and cleanup failures", err)
	}
}

func TestRunScenarioAuditDoesNotChangeFailurePolicy(t *testing.T) {
	for _, auditEnabled := range []bool{false, true} {
		t.Run(fmt.Sprint(auditEnabled), func(t *testing.T) {
			name := fmt.Sprintf("failed_step_%v", auditEnabled)
			var registry module.Registry
			registry.Register(func() module.Generator {
				return &mockGen{
					name:        name,
					generateErr: errors.New("execution failed"),
					events:      []module.TelemetryEvent{{Outcome: module.OutcomeExecuted, Subject: module.Resource("test", "event", "")}},
				}
			})
			var logger *audit.Logger
			if auditEnabled {
				var err error
				logger, err = audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"), "test", "run")
				if err != nil {
					t.Fatal(err)
				}
				defer logger.Close()
			}
			path := writeScenario(t, name, 2, "")
			calls := 0
			_, err := runner.RunScenario(context.Background(), path, func(module.TelemetryEvent) error {
				calls++
				return nil
			}, runner.Options{
				Registry: &registry,
				AuditLog: logger,
			})
			if err == nil || calls != 1 {
				t.Fatalf("error = %v, steps executed = %d; want one failed step", err, calls)
			}
		})
	}
}

func TestRunSinglePrereqFails(t *testing.T) {
	gen := &mockGen{
		name:      "mock_prereq_fail",
		prereqErr: errors.New("not root"),
	}
	err := runner.RunSingle(context.Background(), gen, module.Params{}, discardEvent, runner.Options{})
	if err == nil {
		t.Error("expected error when prereqs fail")
	}
}

func TestRunSingleDryRun(t *testing.T) {
	gen := &mockGen{
		name:        "mock_dryrun",
		prereqErr:   errors.New("native prerequisites should not run during preview"),
		dryRunLines: []string{"action one", "action two"},
		generateErr: errors.New("should not run"),
	}
	err := runner.RunSingle(context.Background(), gen, module.Params{}, discardEvent, runner.Options{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}
	if gen.cleanedUp {
		t.Error("Cleanup should not be called during dry-run")
	}
}

func TestRunSingleTimeout(t *testing.T) {
	slowGen := &slowMockGen{name: "mock_slow", delay: 2 * time.Second}

	err := runner.RunSingle(context.Background(), slowGen, module.Params{}, discardEvent, runner.Options{Timeout: 50 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RunSingle = %v, want context deadline exceeded", err)
	}
	if !slowGen.cleanedUp || slowGen.cleanupCtxErr != nil {
		t.Errorf("cleanup called = %v, cleanup context error = %v", slowGen.cleanedUp, slowGen.cleanupCtxErr)
	}
}

func TestRunManyCollectsErrors(t *testing.T) {
	gens := []module.Generator{
		&mockGen{name: "mock_ok"},
		&mockGen{name: "mock_fail", generateErr: errors.New("boom")},
	}
	err := runner.RunMany(context.Background(), gens, module.Params{}, discardEvent, runner.Options{})
	if err == nil {
		t.Error("expected combined error")
	}
}

type slowMockGen struct {
	name          string
	delay         time.Duration
	cleanedUp     bool
	cleanupCtxErr error
}

func (s *slowMockGen) Info() module.ModuleInfo                                      { return module.ModuleInfo{Name: s.name} }
func (s *slowMockGen) ParamSpecs() []module.ParamSpec                               { return nil }
func (s *slowMockGen) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }
func (s *slowMockGen) Generate(ctx context.Context, _ module.Params, _ module.EventEmitter) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.delay):
		return nil
	}
}
func (s *slowMockGen) DryRun(_ module.Params) []string { return nil }
func (s *slowMockGen) Cleanup(ctx context.Context) error {
	s.cleanedUp = true
	s.cleanupCtxErr = ctx.Err()
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

	err := runner.RunSingle(ctx, gen, module.Params{}, discardEvent, runner.Options{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if !gen.cleanedUp {
		t.Error("expected Cleanup to run after cancellation")
	}
	if gen.cleanupCtxErr != nil {
		t.Errorf("cleanup context error = %v, want independent context", gen.cleanupCtxErr)
	}
}

// countingGen records how many times Generate was invoked and can trigger a
// side-effect (used here to cancel the scenario context mid-run).
type countingGen struct {
	name   string
	onCall func()
}

func (c *countingGen) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: c.name, Category: "test"}
}
func (c *countingGen) ParamSpecs() []module.ParamSpec                               { return nil }
func (c *countingGen) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }
func (c *countingGen) Generate(_ context.Context, _ module.Params, _ module.EventEmitter) error {
	if c.onCall != nil {
		c.onCall()
	}
	return nil
}
func (c *countingGen) DryRun(_ module.Params) []string   { return nil }
func (c *countingGen) Cleanup(ctx context.Context) error { return nil }

// writeScenario builds a temp scenario file invoking moduleName stepCount times.
func writeScenario(t *testing.T, moduleName string, stepCount int, onError string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	body := "version: 1\nname: cancel test\n"
	if onError != "" {
		body += "on_error: " + onError + "\n"
	}
	body += "steps:\n" +
		strings.Repeat("  - module: "+moduleName+"\n", stepCount)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	return path
}

// An interrupted scenario must stop at the step it reached rather than
// fast-failing through every remaining step.
func TestRunScenarioStopsOnCancel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		onError string
	}{
		{name: "stop"},
		{name: "continue", onError: "continue"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			calls := 0
			name := "mock_scenario_step_" + tc.name
			var registry module.Registry
			registry.Register(func() module.Generator {
				return &countingGen{name: name, onCall: func() {
					calls++
					cancel()
				}}
			})

			path := writeScenario(t, name, 4, tc.onError)
			_, err := runner.RunScenario(ctx, path, discardEvent, runner.Options{Registry: &registry})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("expected context.Canceled, got %v", err)
			}
			if calls != 1 {
				t.Errorf("expected scenario to stop after 1 step, ran %d", calls)
			}
		})
	}
}

// Interrupting a scenario must still produce a scenario-level audit record, so
// an operator can see how far the run got before it was cut short.
func TestRunScenarioAuditsInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	name := "mock_audited_step"
	var registry module.Registry
	registry.Register(func() module.Generator {
		return &countingGen{name: name, onCall: cancel}
	})

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.NewLogger(auditPath, "test", "")
	if err != nil {
		t.Fatalf("new audit logger: %v", err)
	}

	path := writeScenario(t, name, 5, "")
	_, runErr := runner.RunScenario(ctx, path, discardEvent, runner.Options{
		Registry: &registry,
		AuditLog: logger,
	})
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
	if got := unmapped["steps_passed"]; got != float64(0) {
		t.Errorf("steps_passed = %v, want 0", got)
	}
	if got := unmapped["steps_failed"]; got != float64(0) {
		t.Errorf("steps_failed = %v, want 0", got)
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

type ctxCapturingGen struct {
	mockGen
	capturedRunID string
}

func (c *ctxCapturingGen) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	c.capturedRunID = module.RunIDFromContext(ctx)
	return c.mockGen.Generate(ctx, params, emit)
}

func TestRunSingle_RunIDInContext(t *testing.T) {
	gen := &ctxCapturingGen{
		mockGen: mockGen{
			name:   "ctx_test",
			events: []module.TelemetryEvent{{Outcome: module.OutcomeExecuted, Subject: module.Resource("test", "event", ""), Category: "test", EventType: "test"}},
		},
	}

	emit := discardEvent
	opts := runner.Options{RunID: "test_run_id_1234"}
	if err := runner.RunSingle(context.Background(), gen, module.Params{}, emit, opts); err != nil {
		t.Fatal(err)
	}
	if gen.capturedRunID != "test_run_id_1234" {
		t.Errorf("RunIDFromContext = %q, want test_run_id_1234", gen.capturedRunID)
	}
	if gen.cleanupRunID != "test_run_id_1234" {
		t.Errorf("cleanup RunIDFromContext = %q, want test_run_id_1234", gen.cleanupRunID)
	}
}

func TestRunScenarioCategoryHonorsOnErrorPerInvocation(t *testing.T) {
	for _, tt := range []struct {
		name      string
		onError   string
		wantCalls int
	}{
		{name: "default_stop", wantCalls: 1},
		{name: "explicit_stop", onError: "stop", wantCalls: 1},
		{name: "continue", onError: "continue", wantCalls: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const category = module.Category("category_policy")
			calls := 0
			var registry module.Registry
			registry.Register(func() module.Generator {
				return &mockGen{
					name:        "a_fail",
					category:    category,
					generateErr: errors.New("execution failed"),
					onGenerate:  func() { calls++ },
				}
			})
			registry.Register(func() module.Generator {
				return &mockGen{
					name:       "b_after",
					category:   category,
					onGenerate: func() { calls++ },
				}
			})

			path := filepath.Join(t.TempDir(), "scenario.yaml")
			body := "version: 1\nname: category policy\n"
			if tt.onError != "" {
				body += "on_error: " + tt.onError + "\n"
			}
			body += "steps:\n  - category: " + string(category) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{Registry: &registry})
			if err == nil {
				t.Fatal("expected scenario failure")
			}
			if calls != tt.wantCalls {
				t.Errorf("module calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestLoadScenarioRejectsInvalidOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nname: invalid\non_error: retry\nsteps:\n  - module: example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.LoadScenario(path); err == nil || !strings.Contains(err.Error(), "invalid on_error") {
		t.Fatalf("LoadScenario error = %v, want invalid on_error", err)
	}
}

func TestLoadScenarioRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scenario.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nname: invalid\ndescripton: typo\nsteps:\n  - module: example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.LoadScenario(path); err == nil || !strings.Contains(err.Error(), "field descripton not found") {
		t.Fatalf("LoadScenario error = %v, want unknown-field error", err)
	}
}

func TestRunScenarioNormalizesPathList(t *testing.T) {
	const name = "path_list"
	var invocation *mockGen
	var registry module.Registry
	registry.Register(func() module.Generator {
		invocation = &mockGen{
			name:       name,
			paramSpecs: []module.ParamSpec{{Name: "paths", Type: module.ParamPathList}},
		}
		return invocation
	})

	path := filepath.Join(t.TempDir(), "scenario.yaml")
	body := "version: 1\nname: typed list\nsteps:\n  - module: " + name + "\n    params:\n      paths:\n        - /tmp/one\n        - /tmp/two\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{Registry: &registry}); err != nil {
		t.Fatal(err)
	}
	if got := invocation.params.Paths("paths", nil); !reflect.DeepEqual(got, []string{"/tmp/one", "/tmp/two"}) {
		t.Fatalf("paths = %#v", got)
	}
}

func TestRunScenarioRejectsUnknownParamBeforeExecution(t *testing.T) {
	const name = "strict_params"
	var invocation *mockGen
	var registry module.Registry
	registry.Register(func() module.Generator {
		invocation = &mockGen{
			name:       name,
			paramSpecs: []module.ParamSpec{{Name: "path", Type: module.ParamPath}},
		}
		return invocation
	})

	path := filepath.Join(t.TempDir(), "scenario.yaml")
	body := "version: 1\nname: strict params\nsteps:\n  - module: " + name + "\n    params:\n      paht: /tmp/typo\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{Registry: &registry})
	if err == nil || invocation.generateCalls != 0 || invocation.cleanedUp {
		t.Fatalf("RunScenario error = %v, invocation = %+v", err, invocation)
	}
}
