package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/pkg/module"
)

// ScenarioReportVersion identifies the JSON execution report contract.
const ScenarioReportVersion = "1.0"

// ScenarioReport is the deterministic, versioned result of one scenario run.
// Step order follows the preflighted execution order.
type ScenarioReport struct {
	SchemaVersion string               `json:"schema_version"`
	Scenario      string               `json:"scenario"`
	Source        string               `json:"source"`
	RunID         string               `json:"run_id,omitempty"`
	Workspace     string               `json:"workspace,omitempty"`
	StartedAt     time.Time            `json:"started_at"`
	FinishedAt    time.Time            `json:"finished_at"`
	Status        string               `json:"status"`
	Inputs        module.Params        `json:"inputs,omitempty"`
	Outputs       module.Params        `json:"outputs,omitempty"`
	Steps         []ScenarioStepReport `json:"steps"`
	Error         string               `json:"error,omitempty"`
}

// ScenarioStepReport records one expanded module invocation or include.
type ScenarioStepReport struct {
	ID            string               `json:"id"`
	Module        string               `json:"module,omitempty"`
	Include       string               `json:"include,omitempty"`
	OnError       string               `json:"on_error"`
	Status        string               `json:"status"`
	StartedAt     time.Time            `json:"started_at,omitempty"`
	FinishedAt    time.Time            `json:"finished_at,omitempty"`
	Outputs       module.Params        `json:"outputs,omitempty"`
	CleanupStatus string               `json:"cleanup_status"`
	CleanupError  string               `json:"cleanup_error,omitempty"`
	Error         string               `json:"error,omitempty"`
	Steps         []ScenarioStepReport `json:"steps,omitempty"`
}

type cleanupTask struct {
	report *ScenarioStepReport
	run    func() error
}

type scenarioExecution struct {
	ctx       context.Context
	registry  *module.Registry
	emit      module.EventEmitter
	opts      Options
	workspace string
	cleanups  []cleanupTask
}

// RunScenario preflights and executes a scenario, then returns its report even
// when execution or cleanup fails.
func RunScenario(ctx context.Context, path string, emit module.EventEmitter, opts Options) (report ScenarioReport, resultErr error) {
	registry := opts.Registry
	if registry == nil {
		registry = &module.DefaultRegistry
	}
	plan, err := preflightScenario(path, opts.ScenarioInputs, registry)
	if err != nil {
		return ScenarioReport{SchemaVersion: ScenarioReportVersion, Source: path, Status: "failed", Error: err.Error()}, err
	}

	workspace, err := os.MkdirTemp("", "macnoise-scenario-")
	if err != nil {
		return ScenarioReport{}, fmt.Errorf("scenario: create workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = os.RemoveAll(workspace)
		return ScenarioReport{}, fmt.Errorf("scenario: secure workspace: %w", err)
	}

	start := time.Now().UTC()
	report = ScenarioReport{
		SchemaVersion: ScenarioReportVersion,
		Scenario:      plan.scenario.Name,
		Source:        plan.path,
		RunID:         opts.RunID,
		Workspace:     workspace,
		StartedAt:     start,
		Status:        "running",
		Inputs:        reportInputs(plan),
	}
	fmt.Fprintf(os.Stderr, "Running scenario: %s\n", plan.scenario.Name)
	if plan.scenario.Description != "" {
		fmt.Fprintf(os.Stderr, "  %s\n", plan.scenario.Description)
	}

	execution := scenarioExecution{ctx: ctx, registry: registry, emit: emit, opts: opts, workspace: workspace}
	inputValues, err := resolvePlanInputs(plan.inputs, nil, nil, false)
	if err == nil {
		var outputs module.Params
		report.Steps, outputs, err = execution.runPlan(plan, inputValues)
		report.Outputs = redactScenarioOutputs(outputs, plan.outputs)
	}
	resultErr = err

	for index := len(execution.cleanups) - 1; index >= 0; index-- {
		task := execution.cleanups[index]
		if cleanupErr := task.run(); cleanupErr != nil {
			task.report.Status = "failed"
			task.report.Error = joinMessage(task.report.Error, cleanupErr.Error())
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}

	if opts.NoCleanup {
		fmt.Fprintf(os.Stderr, "scenario workspace retained at %s (--no-cleanup)\n", workspace)
	} else if cleanupErr := os.RemoveAll(workspace); cleanupErr != nil {
		resultErr = errors.Join(resultErr, fmt.Errorf("scenario: remove workspace: %w", cleanupErr))
	}

	stepsPassed, stepsFailed, totalSteps := reportCounts(report.Steps)
	if opts.AuditLog != nil {
		data := audit.LifecycleData{
			StartTime:   start,
			EndTime:     time.Now().UTC(),
			StepsPassed: stepsPassed,
			StepsFailed: stepsFailed,
			TotalSteps:  totalSteps,
		}
		if resultErr != nil {
			data.GenerateError = resultErr.Error()
		}
		resultErr = errors.Join(resultErr, opts.AuditLog.LogScenario(plan.scenario.Name, plan.path, data))
	}

	report.FinishedAt = time.Now().UTC()
	switch {
	case errors.Is(resultErr, context.Canceled), errors.Is(resultErr, context.DeadlineExceeded):
		report.Status = "interrupted"
	case resultErr != nil:
		report.Status = "failed"
	case opts.DryRun:
		report.Status = "previewed"
	default:
		report.Status = "passed"
	}
	if resultErr != nil {
		report.Error = resultErr.Error()
	}
	return report, resultErr
}

func (e *scenarioExecution) runPlan(plan *scenarioPlan, inputValues module.Params) ([]ScenarioStepReport, module.Params, error) {
	reports := make([]ScenarioStepReport, len(plan.steps))
	stepValues := make(map[string]module.Params)
	var runErr error
	stopped := false

	for index, step := range plan.steps {
		report := &reports[index]
		report.ID = step.id
		report.Module = step.module
		report.Include = step.includePath
		report.OnError = step.policy
		report.Status = "skipped"
		report.CleanupStatus = "not_started"

		if stopped {
			continue
		}
		if err := e.ctx.Err(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("scenario %q interrupted before %s: %w", plan.scenario.Name, step.id, err))
			stopped = true
			continue
		}

		report.StartedAt = time.Now().UTC()
		var stepErr error
		var outputs module.Params
		if step.include != nil {
			childInputs, err := resolvePlanInputs(step.include.inputs, inputValues, stepValues, e.opts.DryRun)
			if err != nil {
				stepErr = err
			} else {
				report.Steps, outputs, stepErr = e.runPlan(step.include, childInputs)
			}
			report.CleanupStatus = "not_applicable"
		} else {
			params, err := resolveBindings(step.params, inputValues, stepValues, e.opts.DryRun, e.moduleParamSpecs(step.module))
			if err != nil {
				stepErr = err
			} else {
				gen, _ := e.registry.Get(step.module)
				invocationOpts := e.opts
				invocationOpts.workspace = e.workspace
				invocationOpts.invocationOutput = &outputs
				registered := false
				invocationOpts.deferCleanup = func(run func() error) {
					registered = true
					report.CleanupStatus = "pending"
					e.cleanups = append(e.cleanups, cleanupTask{report: report, run: run})
				}
				invocationOpts.cleanupResult = func(status, message string) {
					report.CleanupStatus = status
					report.CleanupError = message
				}
				stepErr = RunSingle(e.ctx, gen, params, e.emit, invocationOpts)
				if !registered {
					report.CleanupStatus = "not_required"
				}
				if e.opts.DryRun && stepErr == nil {
					outputs = previewOutputs(step.outputs)
				}
			}
		}
		report.FinishedAt = time.Now().UTC()
		report.Outputs = redactOutputs(outputs, step.outputs)
		stepValues[step.id] = outputs

		if err := e.ctx.Err(); err != nil {
			report.Status = "interrupted"
			report.Error = errors.Join(stepErr, err).Error()
			runErr = errors.Join(runErr, fmt.Errorf("scenario %q interrupted during %s: %w", plan.scenario.Name, step.id, err))
			stopped = true
			continue
		}
		if stepErr != nil {
			report.Status = "failed"
			report.Error = stepErr.Error()
			fmt.Fprintf(os.Stderr, "%s error: %v\n", step.id, stepErr)
			runErr = errors.Join(runErr, fmt.Errorf("%s: %w", step.id, stepErr))
			if step.policy == "stop" {
				stopped = true
			}
			continue
		}
		if e.opts.DryRun {
			report.Status = "previewed"
		} else {
			report.Status = "passed"
		}
	}

	exported := make(module.Params, len(plan.outputs))
	for name, binding := range plan.outputs {
		value, err := resolveBinding(binding, inputValues, stepValues, e.opts.DryRun, module.ParamSpec{Name: name, Type: binding.typeName})
		if err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("scenario %q output %q: %w", plan.scenario.Name, name, err))
			continue
		}
		exported[name] = value
	}
	return reports, exported, runErr
}

func (e *scenarioExecution) moduleParamSpecs(name string) []module.ParamSpec {
	gen, _ := e.registry.Get(name)
	return gen.ParamSpecs()
}

func resolvePlanInputs(bindings map[string]valueBinding, parentInputs module.Params, parentSteps map[string]module.Params, preview bool) (module.Params, error) {
	values := make(module.Params, len(bindings))
	for _, name := range sortedKeys(bindings) {
		binding := bindings[name]
		value, err := resolveBinding(binding, parentInputs, parentSteps, preview, module.ParamSpec{Name: name, Type: binding.typeName})
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", name, err)
		}
		values[name] = value
	}
	return values, nil
}

func resolveBindings(bindings map[string]valueBinding, inputs module.Params, steps map[string]module.Params, preview bool, specs []module.ParamSpec) (module.Params, error) {
	byName := make(map[string]module.ParamSpec, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec
	}
	params := make(module.Params, len(bindings))
	for _, name := range sortedKeys(bindings) {
		value, err := resolveBinding(bindings[name], inputs, steps, preview, byName[name])
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", name, err)
		}
		params[name] = value
	}
	return params, nil
}

func resolveBinding(binding valueBinding, inputs module.Params, steps map[string]module.Params, preview bool, spec module.ParamSpec) (any, error) {
	switch {
	case binding.input != "":
		value, ok := inputs[binding.input]
		if !ok {
			return nil, fmt.Errorf("input %q has no runtime value", binding.input)
		}
		return value, nil
	case binding.ref != nil:
		if outputs, ok := steps[binding.ref.step]; ok {
			if value, ok := outputs[binding.ref.name]; ok {
				return value, nil
			}
		}
		if preview {
			return placeholderValue(spec, binding.label), nil
		}
		return nil, fmt.Errorf("output %s.%s has no runtime value", binding.ref.step, binding.ref.name)
	default:
		return binding.literal, nil
	}
}

func previewOutputs(specs map[string]module.OutputSpec) module.Params {
	outputs := make(module.Params, len(specs))
	for name, spec := range specs {
		outputs[name] = placeholderValue(module.ParamSpec{Name: name, Type: spec.Type}, "runtime:"+name)
	}
	return outputs
}

func redactOutputs(outputs module.Params, specs map[string]module.OutputSpec) module.Params {
	redacted := make(module.Params, len(outputs))
	for name, value := range outputs {
		if specs[name].Sensitive {
			redacted[name] = module.RedactedValue
		} else {
			redacted[name] = value
		}
	}
	return redacted
}

func redactScenarioOutputs(outputs module.Params, specs map[string]valueBinding) module.Params {
	redacted := make(module.Params, len(outputs))
	for name, value := range outputs {
		if specs[name].sensitive {
			redacted[name] = module.RedactedValue
		} else {
			redacted[name] = value
		}
	}
	return redacted
}

func reportInputs(plan *scenarioPlan) module.Params {
	inputs := make(module.Params, len(plan.inputs))
	for name, binding := range plan.inputs {
		switch {
		case binding.sensitive:
			inputs[name] = module.RedactedValue
		case binding.literal != nil:
			inputs[name] = binding.literal
		default:
			inputs[name] = "<" + binding.label + ">"
		}
	}
	return inputs
}

func reportCounts(reports []ScenarioStepReport) (passed, failed, total int) {
	for _, report := range reports {
		if report.Module != "" {
			total++
			switch report.Status {
			case "passed", "previewed":
				passed++
			case "failed":
				failed++
			}
		}
		childPassed, childFailed, childTotal := reportCounts(report.Steps)
		passed += childPassed
		failed += childFailed
		total += childTotal
	}
	return passed, failed, total
}

func joinMessage(first, second string) string {
	if first == "" {
		return second
	}
	return first + "; " + second
}
