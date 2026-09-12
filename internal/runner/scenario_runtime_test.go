package runner_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"
)

type artifactFlow struct {
	mu             sync.Mutex
	cleanupOrder   []string
	generatedPaths map[string]string
	consumedSecret string
	generateCalls  int
}

type artifactModule struct {
	name string
	flow *artifactFlow
	path string
}

func (m *artifactModule) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: m.name, Category: "scenario_test"}
}

func (m *artifactModule) ParamSpecs() []module.ParamSpec {
	switch m.name {
	case "flow_create":
		return []module.ParamSpec{{Name: "content", Type: module.ParamString, Required: true}}
	case "flow_modify":
		return []module.ParamSpec{{Name: "path", Type: module.ParamPath, Required: true}}
	case "flow_archive":
		return []module.ParamSpec{{Name: "source", Type: module.ParamPath, Required: true}}
	case "secret_consumer":
		return []module.ParamSpec{{Name: "secret", Type: module.ParamString, Required: true, Sensitive: true}}
	default:
		return nil
	}
}

func (m *artifactModule) OutputSpecs() []module.OutputSpec {
	switch m.name {
	case "flow_create", "flow_modify":
		return []module.OutputSpec{{Name: "path", Type: module.ParamPath}}
	case "flow_archive":
		return []module.OutputSpec{{Name: "archive", Type: module.ParamPath}}
	case "secret_source":
		return []module.OutputSpec{{Name: "value", Type: module.ParamString, Sensitive: true}}
	default:
		return nil
	}
}

func (m *artifactModule) CheckPrereqs(context.Context, module.Params) error { return nil }

func (m *artifactModule) Generate(ctx context.Context, params module.Params, _ module.EventEmitter) error {
	m.flow.mu.Lock()
	m.flow.generateCalls++
	m.flow.mu.Unlock()
	workspace := module.WorkspaceFromContext(ctx)
	if workspace == "" {
		return errors.New("missing scenario workspace")
	}
	switch m.name {
	case "flow_create":
		m.path = filepath.Join(workspace, "artifact.txt")
		if err := os.WriteFile(m.path, []byte(params.String("content", "")), 0o600); err != nil {
			return err
		}
		m.recordPath(m.path)
		return module.PublishOutput(ctx, "path", m.path)
	case "flow_modify":
		m.path = params.String("path", "")
		data, err := os.ReadFile(m.path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(m.path, append(data, []byte(" modified")...), 0o600); err != nil {
			return err
		}
		m.recordPath(m.path)
		return module.PublishOutput(ctx, "path", m.path)
	case "flow_archive":
		source := params.String("source", "")
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if string(data) != "original modified" {
			return errors.New("archive did not receive modified artifact")
		}
		m.path = filepath.Join(workspace, "artifact.archive")
		if err := os.WriteFile(m.path, data, 0o600); err != nil {
			return err
		}
		m.recordPath(source)
		return module.PublishOutput(ctx, "archive", m.path)
	case "secret_source":
		return module.PublishOutput(ctx, "value", "classified")
	case "secret_consumer":
		m.flow.mu.Lock()
		m.flow.consumedSecret = params.String("secret", "")
		m.flow.mu.Unlock()
		return nil
	default:
		return nil
	}
}

func (m *artifactModule) DryRun(params module.Params) []string {
	return []string{"preview " + m.name}
}

func (m *artifactModule) Cleanup(ctx context.Context) error {
	if module.WorkspaceFromContext(ctx) == "" {
		return errors.New("cleanup lost scenario workspace")
	}
	m.flow.mu.Lock()
	m.flow.cleanupOrder = append(m.flow.cleanupOrder, m.name)
	m.flow.mu.Unlock()
	if m.path != "" && m.name != "flow_modify" {
		return os.Remove(m.path)
	}
	return nil
}

func (m *artifactModule) recordPath(path string) {
	m.flow.mu.Lock()
	defer m.flow.mu.Unlock()
	if m.flow.generatedPaths == nil {
		m.flow.generatedPaths = make(map[string]string)
	}
	m.flow.generatedPaths[m.name] = path
}

func flowRegistry(flow *artifactFlow, names ...string) *module.Registry {
	registry := &module.Registry{}
	for _, name := range names {
		name := name
		registry.Register(func() module.Generator { return &artifactModule{name: name, flow: flow} })
	}
	return registry
}

func writeScenarioFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScenarioDataflowWorkspaceAndReverseCleanup(t *testing.T) {
	flow := &artifactFlow{}
	registry := flowRegistry(flow, "flow_create", "flow_modify", "flow_archive")
	path := writeScenarioFile(t, t.TempDir(), "flow.yaml", `version: 1
name: artifact flow
on_error: stop
inputs:
  content:
    type: string
    required: true
steps:
  - id: create
    module: flow_create
    params:
      content:
        input: content
  - id: modify
    module: flow_modify
    params:
      path:
        output: create.path
  - id: archive
    module: flow_archive
    params:
      source:
        output: modify.path
outputs:
  archive:
    output: archive.archive
`)

	report, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{
		Registry:       registry,
		RunID:          "flow-run",
		ScenarioInputs: module.Params{"content": "original"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || len(report.Steps) != 3 {
		t.Fatalf("report = %+v", report)
	}
	if got, want := flow.cleanupOrder, []string{"flow_archive", "flow_modify", "flow_create"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanup order = %v, want %v", got, want)
	}
	if flow.generatedPaths["flow_create"] != flow.generatedPaths["flow_modify"] || flow.generatedPaths["flow_modify"] != flow.generatedPaths["flow_archive"] {
		t.Fatalf("steps did not consume one artifact: %#v", flow.generatedPaths)
	}
	if _, err := os.Stat(report.Workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace survived cleanup: %v", err)
	}
	for _, step := range report.Steps {
		if step.CleanupStatus != "ok" {
			t.Errorf("%s cleanup = %q", step.ID, step.CleanupStatus)
		}
	}
}

func TestScenarioPreflightRejectsLaterErrorBeforeMutation(t *testing.T) {
	flow := &artifactFlow{}
	registry := flowRegistry(flow, "flow_create")
	path := writeScenarioFile(t, t.TempDir(), "invalid.yaml", `version: 1
name: invalid before mutation
steps:
  - module: flow_create
    params:
      content: should-not-run
  - module: missing_module
`)

	report, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{Registry: registry})
	if err == nil || !strings.Contains(err.Error(), `module "missing_module" not found`) {
		t.Fatalf("RunScenario error = %v", err)
	}
	if flow.generateCalls != 0 {
		t.Fatalf("preflight failure allowed %d mutation(s)", flow.generateCalls)
	}
	if report.Workspace != "" {
		t.Fatalf("preflight failure created workspace %q", report.Workspace)
	}
}

func TestScenarioIncludeDataflowAndCycleValidation(t *testing.T) {
	flow := &artifactFlow{}
	registry := flowRegistry(flow, "secret_source", "secret_consumer")
	dir := t.TempDir()
	writeScenarioFile(t, dir, "child.yaml", `version: 1
name: child
steps:
  - id: source
    module: secret_source
outputs:
  secret:
    output: source.value
`)
	parent := writeScenarioFile(t, dir, "parent.yaml", `version: 1
name: parent
steps:
  - id: child
    include: child.yaml
  - module: secret_consumer
    params:
      secret:
        output: child.secret
`)

	report, err := runner.RunScenario(context.Background(), parent, discardEvent, runner.Options{Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	if flow.consumedSecret != "classified" {
		t.Fatalf("include output = %q", flow.consumedSecret)
	}
	if len(report.Steps[0].Steps) != 1 || report.Steps[0].Outputs["secret"] != module.RedactedValue {
		t.Fatalf("include report did not redact output: %+v", report.Steps[0])
	}

	writeScenarioFile(t, dir, "a.yaml", "version: 1\nname: a\nsteps:\n  - include: b.yaml\n")
	b := writeScenarioFile(t, dir, "b.yaml", "version: 1\nname: b\nsteps:\n  - include: a.yaml\n")
	if err := runner.ValidateScenario(b, nil, registry); err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("cycle validation error = %v", err)
	}

	for index := 0; index < 10; index++ {
		body := "version: 1\nname: depth\nsteps:\n"
		if index == 9 {
			body += "  - module: secret_source\n"
		} else {
			body += "  - include: depth_" + strconv.Itoa(index+1) + ".yaml\n"
		}
		writeScenarioFile(t, dir, "depth_"+strconv.Itoa(index)+".yaml", body)
	}
	if err := runner.ValidateScenario(filepath.Join(dir, "depth_0.yaml"), nil, registry); err == nil || !strings.Contains(err.Error(), "include depth exceeds") {
		t.Fatalf("depth validation error = %v", err)
	}
}

func TestScenarioStepFailurePolicyAndOutputContract(t *testing.T) {
	flow := &artifactFlow{}
	registry := flowRegistry(flow, "secret_consumer")
	registry.Register(func() module.Generator { return &missingOutputModule{} })
	path := writeScenarioFile(t, t.TempDir(), "continue.yaml", `version: 1
name: continue one invocation
on_error: stop
steps:
  - module: missing_output
    on_error: continue
  - module: secret_consumer
    params:
      secret: reached
`)

	report, err := runner.RunScenario(context.Background(), path, discardEvent, runner.Options{Registry: registry})
	if err == nil || !strings.Contains(err.Error(), `did not publish declared output "value"`) {
		t.Fatalf("RunScenario error = %v", err)
	}
	if flow.consumedSecret != "reached" || report.Steps[0].OnError != "continue" || report.Steps[1].Status != "passed" {
		t.Fatalf("per-invocation policy report = %+v, consumed = %q", report, flow.consumedSecret)
	}
}

type missingOutputModule struct{}

func (*missingOutputModule) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: "missing_output", Category: "scenario_test"}
}
func (*missingOutputModule) ParamSpecs() []module.ParamSpec { return nil }
func (*missingOutputModule) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{{Name: "value", Type: module.ParamString}}
}
func (*missingOutputModule) CheckPrereqs(context.Context, module.Params) error { return nil }
func (*missingOutputModule) Generate(context.Context, module.Params, module.EventEmitter) error {
	return nil
}
func (*missingOutputModule) DryRun(module.Params) []string { return nil }
func (*missingOutputModule) Cleanup(context.Context) error { return nil }

func TestScenarioCancellationOverridesContinueAndCleansUp(t *testing.T) {
	flow := &artifactFlow{}
	registry := flowRegistry(flow, "flow_create", "flow_modify")
	ctx, cancel := context.WithCancel(context.Background())
	registry.Register(func() module.Generator {
		return &cancelModule{name: "cancel_now", cancel: cancel, flow: flow}
	})
	path := writeScenarioFile(t, t.TempDir(), "cancel.yaml", `version: 1
name: cancel
on_error: continue
steps:
  - module: flow_create
    params:
      content: original
  - module: cancel_now
  - module: flow_modify
    params:
      path: never
`)

	report, err := runner.RunScenario(ctx, path, discardEvent, runner.Options{Registry: registry})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunScenario error = %v", err)
	}
	if report.Status != "interrupted" || report.Steps[2].Status != "skipped" {
		t.Fatalf("cancellation report = %+v", report)
	}
	if got, want := flow.cleanupOrder, []string{"cancel_now", "flow_create"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanup order = %v, want %v", got, want)
	}
}

type cancelModule struct {
	name   string
	cancel context.CancelFunc
	flow   *artifactFlow
}

func (m *cancelModule) Info() module.ModuleInfo {
	return module.ModuleInfo{Name: m.name, Category: "scenario_test"}
}
func (m *cancelModule) ParamSpecs() []module.ParamSpec                    { return nil }
func (m *cancelModule) CheckPrereqs(context.Context, module.Params) error { return nil }
func (m *cancelModule) Generate(context.Context, module.Params, module.EventEmitter) error {
	m.flow.mu.Lock()
	m.flow.generateCalls++
	m.flow.mu.Unlock()
	m.cancel()
	return nil
}
func (m *cancelModule) DryRun(module.Params) []string { return nil }
func (m *cancelModule) Cleanup(context.Context) error {
	m.flow.mu.Lock()
	defer m.flow.mu.Unlock()
	m.flow.cleanupOrder = append(m.flow.cleanupOrder, m.name)
	return nil
}
