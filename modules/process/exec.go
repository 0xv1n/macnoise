package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procExec struct{}

func (p *procExec) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_exec",
		EventTypes:  []string{"process_exec"},
		Description: "Executes an explicit argument vector without invoking an implicit shell",
		Category:    module.CategoryProcess,
		Tags:        []string{"execution", "argv", "process"},
		Privileges:  module.PrivilegeNone,
		Author:      "0xv1n",
		MinMacOS:    "12.0",
	}
}

func (p *procExec) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "executable", Description: "Executable name or path", Type: module.ParamString, Default: "/usr/bin/true", Example: "/usr/bin/id"},
		{Name: "args", Description: "Exact arguments passed to the executable", Type: module.ParamStringList, Sensitive: true, Default: []string{}, Example: []string{"-un"}},
		{Name: "working_dir", Description: "Working directory for the process", Type: module.ParamPath, Default: "", Example: "/Volumes/Delivery"},
		{Name: "accept_nonzero", Description: "Treat a completed non-zero exit as generated telemetry", Type: module.ParamBoolean, Default: false, Example: true},
	}
}

func (p *procExec) OutputSpecs() []module.OutputSpec {
	return []module.OutputSpec{
		{Name: "output", Description: "Combined standard output and standard error", Type: module.ParamString, Sensitive: true},
		{Name: "exit_code", Description: "Process exit code", Type: module.ParamInteger},
	}
}

func (p *procExec) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (p *procExec) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	executable := params.String("executable", "/usr/bin/true")
	args := params.Strings("args", nil)
	workingDir := params.String("working_dir", "")
	argv := append([]string{executable}, args...)
	info := p.Info()
	subjectExecutable := executable
	if workingDir != "" && !filepath.IsAbs(executable) {
		subjectExecutable = filepath.Join(workingDir, executable)
	}
	ev := output.NewEvent(info, "process_exec", module.OutcomeError,
		module.Process(filepath.Base(executable), subjectExecutable, executable, 0),
		fmt.Sprintf("executing %s with %d argument(s)", executable, len(args)))

	result, runErr := subprocess.RunInDir(ctx, workingDir, executable, args...)
	if ctx.Err() != nil {
		return errors.Join(runErr, ctx.Err())
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			ev = output.WithError(ev, runErr)
			return errors.Join(runErr, emit(ev))
		}
	}

	publishErr := errors.Join(
		module.PublishOutput(ctx, "output", string(result.Output)),
		module.PublishOutput(ctx, "exit_code", result.ExitCode),
	)
	details := map[string]any{"argv": argv, "output": string(result.Output), "exit_code": result.ExitCode}
	if workingDir != "" {
		details["working_directory"] = workingDir
	}
	if runErr != nil && !params.Bool("accept_nonzero", false) {
		ev = output.WithError(ev, runErr)
		ev = output.WithDetails(ev, details)
		return errors.Join(runErr, publishErr, emit(ev))
	}

	ev.Outcome = module.OutcomeExecuted
	if runErr != nil {
		ev.Message = fmt.Sprintf("%s exited %d (accepted)", executable, result.ExitCode)
		details["error"] = runErr.Error()
	} else {
		ev.Message = fmt.Sprintf("%s exited 0", executable)
	}
	ev = output.WithDetails(ev, details)
	return errors.Join(publishErr, emit(ev))
}

func (p *procExec) DryRun(params module.Params) []string {
	argv := append([]string{params.String("executable", "/usr/bin/true")}, params.Strings("args", nil)...)
	quoted := make([]string, len(argv))
	for index, arg := range argv {
		quoted[index] = strconv.Quote(arg)
	}
	line := "exec: " + strings.Join(quoted, " ")
	if workingDir := params.String("working_dir", ""); workingDir != "" {
		line = fmt.Sprintf("exec in %s: %s", workingDir, strings.Join(quoted, " "))
	}
	return []string{line}
}

func (p *procExec) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &procExec{} })
}
