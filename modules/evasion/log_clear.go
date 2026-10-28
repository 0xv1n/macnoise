package evasion

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/ownership"
	"github.com/0xv1n/macnoise/pkg/module"
)

const defaultEvasionStageDir = "/tmp/macnoise_evasion"

type evadeLogClear struct {
	timestompTarget ownership.File
	createdDirs     []ownership.Directory
}

func (e *evadeLogClear) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "evade_log_clear",
		EventTypes:  []string{"file_timestomp", "log_erase_attempt", "history_clear"},
		Description: "Timestomps a file, attempts unified log erasure, and removes real shell history files",
		Category:    module.CategoryEvasion,
		Tags:        []string{"evasion", "anti-forensics", "timestomp", "log-clear", "history"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1070", SubTech: ".006", Name: "Indicator Removal: Timestomp"},
			{Technique: "T1070", SubTech: ".002", Name: "Indicator Removal: Clear Linux or Mac System Logs"},
			{Technique: "T1070", SubTech: ".003", Name: "Indicator Removal: Clear Command History"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (e *evadeLogClear) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:        "stage_dir",
			Description: "Directory for staging evasion artifacts",
			Type:        module.ParamPath,
			Default:     defaultEvasionStageDir,
			Example:     "/var/tmp/macnoise_evasion",
		},
		{
			Name:        "history_paths",
			Description: "Real shell history files to remove (defaults to the current user's zsh and bash histories)",
			Type:        module.ParamPathList,
			Example:     []string{"/Users/test/.zsh_history", "/Users/test/.bash_history"},
		},
	}
}

func (e *evadeLogClear) CheckPrereqs(ctx context.Context, params module.Params) error {
	_, err := historyPaths(params)
	return err
}

func historyPaths(params module.Params) ([]string, error) {
	if paths := params.Paths("history_paths", nil); len(paths) > 0 {
		return paths, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve current user home for shell history: %w", err)
	}
	return []string{
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".bash_history"),
	}, nil
}

// timestomp creates a file and sets its mtime to a date in the past.
// The os.Chtimes call generates the utimes syscall that an EDR fires on,
// and is cross-platform testable unlike touch -t.
func timestomp(info module.ModuleInfo, target string) (module.TelemetryEvent, ownership.File, error) {
	owned, err := ownership.CreateFile(target, []byte("macnoise timestomp target\n"), 0o644)
	if err != nil {
		ev := output.NewEvent(info, "file_timestomp", module.OutcomeError, module.File(target),
			fmt.Sprintf("failed to create timestomp target: %s", target))
		return output.WithError(ev, err), ownership.File{}, err
	}

	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	err = os.Chtimes(target, past, past)
	if err != nil {
		ev := output.NewEvent(info, "file_timestomp", module.OutcomeDenied, module.File(target),
			fmt.Sprintf("timestomp denied: %s", target))
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"path":         target,
			"target_mtime": past.Format(time.RFC3339),
			"technique":    "T1070.006",
		}), owned, nil
	}

	ev := output.NewEvent(info, "file_timestomp", module.OutcomeExecuted, module.File(target),
		fmt.Sprintf("timestomped %s to %s", target, past.Format("2006-01-02")))
	return output.WithDetails(ev, map[string]any{
		"path":         target,
		"target_mtime": past.Format(time.RFC3339),
		"technique":    "T1070.006",
	}), owned, nil
}

// logErase attempts `log erase --all`. Without root this fails, and the
// denied exec is exactly the telemetry a detection should fire on.
func logErase(ctx context.Context, info module.ModuleInfo) module.TelemetryEvent {
	out, err := exec.CommandContext(ctx, "log", "erase", "--all").CombinedOutput()
	if err != nil {
		ev := output.NewEvent(info, "log_erase_attempt", module.OutcomeDenied,
			module.Process("log", "/usr/bin/log", "log erase --all", 0),
			"log erase --all denied (expected without root)")
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"command":   "log erase --all",
			"output":    string(out),
			"technique": "T1070.002",
		})
	}

	ev := output.NewEvent(info, "log_erase_attempt", module.OutcomeExecuted,
		module.Process("log", "/usr/bin/log", "log erase --all", 0),
		"log erase --all succeeded")
	return output.WithDetails(ev, map[string]any{
		"command":   "log erase --all",
		"output":    string(out),
		"technique": "T1070.002",
	})
}

// clearHistory removes one real shell history file. This is the adversary
// action itself, so cleanup does not restore it.
func clearHistory(info module.ModuleInfo, path string) (module.TelemetryEvent, error) {
	ev := output.NewEvent(info, "history_clear", module.OutcomeError, module.File(path),
		fmt.Sprintf("removing shell history: %s", path))
	err := os.Remove(path)
	switch {
	case err == nil:
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("shell history removed: %s", path)
	case os.IsNotExist(err):
		ev = output.WithOutcome(ev, module.OutcomeIndeterminate, err)
		ev.Message = fmt.Sprintf("shell history was not present: %s", path)
	case os.IsPermission(err):
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		ev.Message = fmt.Sprintf("shell history removal denied: %s", path)
	default:
		ev = output.WithError(ev, err)
	}
	ev = output.WithDetails(ev, map[string]any{
		"path":      path,
		"technique": "T1070.003",
	})
	if ev.Outcome == module.OutcomeError {
		return ev, err
	}
	return ev, nil
}

func (e *evadeLogClear) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := e.Info()
	histories, err := historyPaths(params)
	if err != nil {
		return err
	}
	stageDir := module.TagPath(params.String("stage_dir", defaultEvasionStageDir), module.RunIDFromContext(ctx))
	createdDirs, err := ownership.EnsureDirectories(stageDir, 0o755)
	e.createdDirs = append(e.createdDirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	timestompEv, owned, timestompErr := timestomp(info, filepath.Join(stageDir, "timestomp_target"))
	e.timestompTarget = owned
	if err := emit(timestompEv); err != nil {
		return err
	}
	resultErr := timestompErr

	select {
	case <-ctx.Done():
		return errors.Join(resultErr, ctx.Err())
	default:
	}
	if err := emit(logErase(ctx, info)); err != nil {
		return errors.Join(resultErr, err)
	}

	for _, path := range histories {
		select {
		case <-ctx.Done():
			return errors.Join(resultErr, ctx.Err())
		default:
		}
		historyEv, historyErr := clearHistory(info, path)
		resultErr = errors.Join(resultErr, historyErr)
		if err := emit(historyEv); err != nil {
			return errors.Join(resultErr, err)
		}
	}
	return resultErr
}

func (e *evadeLogClear) DryRun(params module.Params) []string {
	stageDir := params.String("stage_dir", defaultEvasionStageDir)
	histories, err := historyPaths(params)
	if err != nil {
		histories = []string{"~/.zsh_history", "~/.bash_history"}
	}
	steps := []string{
		fmt.Sprintf("mkdir -p %s", stageDir),
		fmt.Sprintf("touch -t 200001010000 %s/timestomp_target (T1070.006)", stageDir),
		"log erase --all (T1070.002, requires root)",
	}
	for _, path := range histories {
		steps = append(steps, fmt.Sprintf("remove real shell history %s (T1070.003)", path))
	}
	return steps
}

func (e *evadeLogClear) Cleanup(ctx context.Context) error {
	return errors.Join(e.timestompTarget.Remove(), ownership.RemoveDirectories(e.createdDirs))
}

func init() {
	module.Register(func() module.Generator { return &evadeLogClear{} })
}
