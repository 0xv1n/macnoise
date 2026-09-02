package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procInject struct{}

// injectOutcome records whether dyld actually acted on DYLD_INSERT_LIBRARIES.
type injectOutcome string

const (
	injectHonored       injectOutcome = "honored"
	injectStripped      injectOutcome = "stripped"
	injectIndeterminate injectOutcome = "indeterminate"
)

func (p *procInject) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_inject",
		Description: "Spawns a process with DYLD_INSERT_LIBRARIES to generate dylib injection telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"dylib", "injection", "execution", "dyld"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1574", SubTech: ".006", Name: "Hijack Execution Flow: Dynamic Linker Hijacking"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procInject) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "dylib_path", Description: "Path to the dylib to insert; it need not exist, dyld's refusal to find it is itself the evidence", Required: false, DefaultValue: "/tmp/macnoise_inject.dylib", Example: "/tmp/evil.dylib"},
		{Name: "target", Description: "Binary to spawn with the injection env (defaults to macnoise itself, which is injectable)", Required: false, DefaultValue: "", Example: "/tmp/my_unsigned_binary"},
	}
}

func (p *procInject) CheckPrereqs() error { return nil }

// defaultTarget returns macnoise's own executable.
//
// System binaries under /usr/bin and /bin cannot be used: they are protected,
// and dyld drops DYLD_INSERT_LIBRARIES before the process starts, so the
// injection path is never exercised. Verified on macOS 26 that this holds even
// for a copy of the binary with its signature removed or re-signed ad-hoc, so
// there is no way to derive a usable target from a system binary. macnoise is
// built locally and is only ad-hoc signed, so dyld honours the variable, and
// it is guaranteed present on any host running this module.
func defaultTarget() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine own executable path: %w", err)
	}
	return exe, nil
}

// classifyInjection reports whether dyld acted on DYLD_INSERT_LIBRARIES.
//
// A protected target has the variable stripped before dyld sees it, and the
// process then runs normally with no diagnostic at all. So when the dylib does
// not exist, a dyld complaint proves the variable survived and its absence
// proves it did not. When the dylib does exist and loads cleanly there is no
// diagnostic either way, and the outcome is reported as indeterminate rather
// than guessed.
func classifyInjection(dylibExists bool, stderr string) injectOutcome {
	if strings.Contains(stderr, "inserted dylib") {
		return injectHonored
	}
	if dylibExists {
		return injectIndeterminate
	}
	return injectStripped
}

func (p *procInject) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	dylibPath := module.TagPath(params.Get("dylib_path", "/tmp/macnoise_inject.dylib"), module.RunIDFromContext(ctx))
	targetBin := params.Get("target", "")
	if targetBin == "" {
		var err error
		if targetBin, err = defaultTarget(); err != nil {
			return err
		}
	}
	info := p.Info()

	var stderr strings.Builder
	cmd := exec.CommandContext(ctx, targetBin)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("DYLD_INSERT_LIBRARIES=%s", dylibPath))
	cmd.Stderr = &stderr

	// The child's exit status is deliberately not treated as failure. dyld
	// aborts the process when an inserted dylib cannot be loaded, so the
	// successful injection path exits non-zero by design.
	runErr := cmd.Run()

	_, statErr := os.Stat(dylibPath)
	outcome := classifyInjection(statErr == nil, stderr.String())

	ev := output.NewEvent(info, "dylib_inject_attempt", true,
		fmt.Sprintf("spawned %s with DYLD_INSERT_LIBRARIES=%s", targetBin, dylibPath))
	details := map[string]any{
		"target":           targetBin,
		"dyld_insert_libs": dylibPath,
		"outcome":          string(outcome),
	}

	switch outcome {
	case injectHonored:
		ev.Message = fmt.Sprintf("dyld honoured DYLD_INSERT_LIBRARIES for %s", targetBin)
	case injectStripped:
		ev.Message = fmt.Sprintf("%s stripped DYLD_INSERT_LIBRARIES before dyld ran; the target is protected", targetBin)
		ev = output.WithOutcome(ev, module.OutcomeDenied, nil)
	default:
		ev.Message = fmt.Sprintf("spawned %s with DYLD_INSERT_LIBRARIES=%s, dyld raised no diagnostic", targetBin, dylibPath)
		ev = output.WithOutcome(ev, module.OutcomeIndeterminate, nil)
	}
	if runErr != nil {
		details["exit_error"] = runErr.Error()
	}

	emit(output.WithDetails(ev, details))
	return nil
}

func (p *procInject) DryRun(params module.Params) []string {
	dylib := params.Get("dylib_path", "/tmp/macnoise_inject.dylib")
	target := params.Get("target", "")
	if target == "" {
		target, _ = defaultTarget()
	}
	return []string{
		fmt.Sprintf("spawn %s with env DYLD_INSERT_LIBRARIES=%s", target, dylib),
	}
}

func (p *procInject) Cleanup() error { return nil }

func init() {
	module.Register(&procInject{})
}
