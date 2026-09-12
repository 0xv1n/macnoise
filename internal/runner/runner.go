// Package runner orchestrates the execution of macnoise telemetry modules.
// It provides RunSingle for individual module execution, RunMany for sequential
// batch execution, and RunScenario for YAML-driven multi-step execution. When
// an audit.Logger is provided in Options, lifecycle records are written for
// each module run alongside the normal telemetry event stream.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

// Options controls module execution behaviour in RunSingle, RunMany, and RunScenario.
type Options struct {
	Registry *module.Registry
	DryRun   bool
	// NoCleanup leaves module artifacts in place after Generate. Validation
	// workflows need the installed artifact to persist so the persistence
	// itself can be detected, not just the install event.
	NoCleanup bool
	Timeout   time.Duration
	Verbose   bool
	AuditLog  *audit.Logger
	// RunID is the correlation identifier for this invocation. Modules
	// retrieve it via module.RunIDFromContext so they can fold it into
	// artifact names, DNS labels, and command arguments.
	RunID string
	// ScenarioInputs supplies typed values declared by a scenario. It is
	// ignored by RunSingle and RunMany.
	ScenarioInputs module.Params

	workspace        string
	deferCleanup     func(func() error)
	cleanupResult    func(string, string)
	invocationOutput *module.Params
}

// RunSingle executes one module through its full lifecycle (prereqs → generate → cleanup).
func RunSingle(ctx context.Context, gen module.Generator, params module.Params, emit module.EventEmitter, opts Options) (resultErr error) {
	info := gen.Info()
	normalized, err := module.NormalizeParams(gen.ParamSpecs(), params)
	if err != nil {
		return fmt.Errorf("[%s] params: %w", info.Name, err)
	}
	params = normalized
	auditParams := module.RedactParams(gen.ParamSpecs(), params)
	startTime := time.Now()

	lifecycle := audit.LifecycleData{
		StartTime: startTime,
		DryRun:    opts.DryRun,
	}

	runCtx := module.ContextWithRunID(ctx, opts.RunID)
	if opts.workspace != "" {
		runCtx = module.ContextWithWorkspace(runCtx, opts.workspace)
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(runCtx, opts.Timeout)
		defer cancel()
	}
	if err := runCtx.Err(); err != nil {
		return err
	}
	if !opts.DryRun {
		if err := gen.CheckPrereqs(runCtx, params); err != nil {
			lifecycle.PrereqResult = "fail"
			lifecycle.PrereqError = err.Error()
			if opts.AuditLog != nil {
				lifecycle.EndTime = time.Now()
				auditErr := opts.AuditLog.LogLifecycle("module_prereq_fail", info, auditParams, lifecycle)
				return errors.Join(fmt.Errorf("[%s] prereqs: %w", info.Name, err), auditErr)
			}
			return fmt.Errorf("[%s] prereqs: %w", info.Name, err)
		}
	}
	lifecycle.PrereqResult = "pass"

	if opts.DryRun {
		for _, action := range gen.DryRun(params) {
			fmt.Fprintf(os.Stderr, "[dry-run] [%s] %s\n", info.Name, action)
		}
		if opts.AuditLog != nil {
			lifecycle.EndTime = time.Now()
			if err := opts.AuditLog.LogLifecycle("module_dry_run", info, auditParams, lifecycle); err != nil {
				return err
			}
		}
		return nil
	}

	var eventsEmitted int
	eventEmit := emit
	if opts.AuditLog != nil {
		eventEmit = opts.AuditLog.WrapEmitter(emit, info, auditParams, &eventsEmitted)
	}
	var emitMu sync.Mutex
	var emitErr error
	normalizedEmit := func(ev module.TelemetryEvent) error {
		ev, err := output.NormalizeEvent(info, ev)
		if err == nil {
			err = eventEmit(ev)
		}
		if err != nil {
			emitMu.Lock()
			emitErr = errors.Join(emitErr, err)
			emitMu.Unlock()
		}
		return err
	}

	collector := newOutputCollector(gen)
	runCtx = module.ContextWithOutputSink(runCtx, collector.publish)

	var generateErr error
	defer func() {
		finish := func() error {
			cleanupResult := "ok"
			cleanupErrStr := ""
			var finishErr error
			switch {
			case opts.NoCleanup:
				// Always announced, not gated behind --verbose: leaving real
				// persistence installed is the kind of thing an operator must not
				// discover later by accident.
				cleanupResult = "skipped"
				fmt.Fprintf(os.Stderr, "[%s] cleanup skipped (--no-cleanup); artifacts left in place, see 'macnoise info %s'\n", info.Name, info.Name)
			default:
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(runCtx), 10*time.Second)
				defer cancel()
				if err := gen.Cleanup(cleanupCtx); err != nil {
					cleanupResult = "error"
					cleanupErrStr = err.Error()
					finishErr = fmt.Errorf("[%s] cleanup: %w", info.Name, err)
					fmt.Fprintf(os.Stderr, "[%s] cleanup error: %v\n", info.Name, err)
				}
			}
			if opts.cleanupResult != nil {
				opts.cleanupResult(cleanupResult, cleanupErrStr)
			}
			if opts.AuditLog != nil {
				lifecycle.EndTime = time.Now()
				lifecycle.EventsEmitted = eventsEmitted
				lifecycle.CleanupResult = cleanupResult
				lifecycle.CleanupError = cleanupErrStr
				if generateErr != nil {
					lifecycle.GenerateError = generateErr.Error()
				}
				finishErr = errors.Join(finishErr, opts.AuditLog.LogLifecycle("module_run", info, auditParams, lifecycle))
			}
			return finishErr
		}
		if opts.deferCleanup != nil {
			opts.deferCleanup(finish)
			return
		}
		resultErr = errors.Join(resultErr, finish())
	}()

	generateErr = gen.Generate(runCtx, params, normalizedEmit)
	if outputErr := collector.err(); outputErr != nil && !errors.Is(generateErr, outputErr) {
		generateErr = errors.Join(generateErr, outputErr)
	}
	if generateErr == nil {
		generateErr = collector.requireAll()
	}
	if opts.invocationOutput != nil {
		*opts.invocationOutput = collector.values()
	}
	emitMu.Lock()
	if emitErr != nil && !errors.Is(generateErr, emitErr) {
		generateErr = errors.Join(generateErr, emitErr)
	}
	emitMu.Unlock()
	if runCtx.Err() != nil {
		generateErr = errors.Join(generateErr, runCtx.Err())
	}
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
