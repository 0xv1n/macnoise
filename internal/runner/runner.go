// Package runner orchestrates the execution of macnoise telemetry modules.
// It provides RunSingle for individual module execution, RunMany for sequential
// batch execution, and RunScenario for YAML-driven multi-step execution. When
// an audit.Logger is provided in Options, lifecycle records are written for
// each module run alongside the normal telemetry event stream.
package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/pkg/module"
)

// Options controls module execution behaviour in RunSingle, RunMany, and RunScenario.
type Options struct {
	DryRun   bool
	Timeout  time.Duration
	Verbose  bool
	AuditLog *audit.Logger
}

// RunSingle executes one module through its full lifecycle (prereqs → generate → cleanup).
func RunSingle(ctx context.Context, gen module.Generator, params module.Params, emit module.EventEmitter, opts Options) error {
	info := gen.Info()
	startTime := time.Now()

	lifecycle := audit.LifecycleData{
		StartTime: startTime,
		DryRun:    opts.DryRun,
	}

	if err := gen.CheckPrereqs(); err != nil {
		lifecycle.PrereqResult = "fail"
		lifecycle.PrereqError = err.Error()
		if opts.AuditLog != nil {
			lifecycle.EndTime = time.Now()
			opts.AuditLog.LogLifecycle("module_prereq_fail", info, params, lifecycle)
		}
		return fmt.Errorf("[%s] prereqs: %w", info.Name, err)
	}
	lifecycle.PrereqResult = "pass"

	if opts.DryRun {
		for _, action := range gen.DryRun(params) {
			fmt.Printf("[dry-run] [%s] %s\n", info.Name, action)
		}
		if opts.AuditLog != nil {
			lifecycle.EndTime = time.Now()
			opts.AuditLog.LogLifecycle("module_dry_run", info, params, lifecycle)
		}
		return nil
	}

	var eventsEmitted int
	auditEmit := emit
	if opts.AuditLog != nil {
		auditEmit = opts.AuditLog.WrapEmitter(emit, info, params, &eventsEmitted)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var generateErr error
	defer func() {
		cleanupResult := "ok"
		cleanupErrStr := ""
		if err := gen.Cleanup(); err != nil {
			cleanupResult = "error"
			cleanupErrStr = err.Error()
			if opts.Verbose {
				fmt.Printf("[%s] cleanup error: %v\n", info.Name, err)
			}
		}
		if opts.AuditLog != nil {
			lifecycle.EndTime = time.Now()
			lifecycle.EventsEmitted = eventsEmitted
			lifecycle.CleanupResult = cleanupResult
			lifecycle.CleanupError = cleanupErrStr
			if generateErr != nil {
				lifecycle.GenerateError = generateErr.Error()
			}
			opts.AuditLog.LogLifecycle("module_run", info, params, lifecycle)
		}
	}()

	generateErr = gen.Generate(runCtx, params, auditEmit)
	return generateErr
}

// RunMany sequentially executes each generator in gens, collecting errors without aborting early.
func RunMany(ctx context.Context, gens []module.Generator, params module.Params, emit module.EventEmitter, opts Options) error {
	var errs []error
	for _, g := range gens {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := RunSingle(ctx, g, params, emit, opts); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d module(s) failed: %v", len(errs), errs)
	}
	return nil
}

// RunScenario loads the YAML scenario at path and executes its steps in order.
func RunScenario(ctx context.Context, path string, emit module.EventEmitter, opts Options) error {
	sc, err := LoadScenario(path)
	if err != nil {
		return err
	}

	fmt.Printf("Running scenario: %s\n", sc.Name)
	if sc.Description != "" {
		fmt.Printf("  %s\n", sc.Description)
	}

	scenarioStart := time.Now()
	stepsPassed := 0
	stepsFailed := 0

	for i, step := range sc.Steps {
		params := module.Params(step.Params)
		if params == nil {
			params = module.Params{}
		}

		var stepErr error
		switch {
		case step.Module != "":
			gen, ok := module.Get(step.Module)
			if !ok {
				stepErr = fmt.Errorf("scenario step %d: module %q not found", i+1, step.Module)
			} else {
				stepErr = RunSingle(ctx, gen, params, emit, opts)
			}

		case step.Category != "":
			cat := module.Category(step.Category)
			gens := module.ByCategory(cat)
			if len(gens) == 0 {
				stepErr = fmt.Errorf("scenario step %d: no modules found for category %q", i+1, step.Category)
			} else {
				stepErr = RunMany(ctx, gens, params, emit, opts)
			}

		default:
			stepErr = fmt.Errorf("scenario step %d: must specify either 'module' or 'category'", i+1)
		}

		if stepErr != nil {
			stepsFailed++
			if opts.AuditLog == nil {
				return stepErr
			}
			fmt.Printf("step %d error: %v\n", i+1, stepErr)
		} else {
			stepsPassed++
		}
	}

	if opts.AuditLog != nil {
		ld := audit.LifecycleData{
			StartTime:   scenarioStart,
			EndTime:     time.Now(),
			StepsPassed: stepsPassed,
			StepsFailed: stepsFailed,
			TotalSteps:  len(sc.Steps),
		}
		if stepsFailed > 0 {
			ld.GenerateError = fmt.Sprintf("%d step(s) failed", stepsFailed)
		}
		opts.AuditLog.LogScenario(sc.Name, path, ld)
	}

	if stepsFailed > 0 {
		return fmt.Errorf("scenario %q: %d of %d step(s) failed", sc.Name, stepsFailed, len(sc.Steps))
	}
	return nil
}
