package process

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procInject struct{}

func (p *procInject) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_inject",
		Description: "Spawns a process with DYLD_INSERT_LIBRARIES to simulate dylib injection telemetry",
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
		{Name: "dylib_path", Description: "Path to dylib to inject (does not need to exist — env var is the telemetry)", Required: false, DefaultValue: "/tmp/macnoise_inject.dylib", Example: "/tmp/evil.dylib"},
		{Name: "target", Description: "Target binary to spawn with injection env", Required: false, DefaultValue: "/usr/bin/true", Example: "/bin/ls"},
	}
}

func (p *procInject) CheckPrereqs() error { return nil }

func (p *procInject) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	dylibPath := params.Get("dylib_path", "/tmp/macnoise_inject.dylib")
	targetBin := params.Get("target", "/usr/bin/true")
	info := p.Info()

	cmd := exec.CommandContext(ctx, targetBin)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("DYLD_INSERT_LIBRARIES=%s", dylibPath))

	ev := output.NewEvent(info, "dylib_inject_attempt", false,
		fmt.Sprintf("spawning %s with DYLD_INSERT_LIBRARIES=%s", targetBin, dylibPath))

	err := cmd.Run()
	if err != nil && err.Error() == "exit status 1" {
		err = nil
	}
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("process spawned with DYLD_INSERT_LIBRARIES=%s (SIP may strip on macOS)", dylibPath)
	ev = output.WithDetails(ev, map[string]any{
		"target":           targetBin,
		"dyld_insert_libs": dylibPath,
		"sip_note":         "SIP-protected binaries will strip the env var; telemetry still generated",
	})
	emit(ev)
	return nil
}

func (p *procInject) DryRun(params module.Params) []string {
	dylib := params.Get("dylib_path", "/tmp/macnoise_inject.dylib")
	target := params.Get("target", "/usr/bin/true")
	return []string{
		fmt.Sprintf("spawn %s with env DYLD_INSERT_LIBRARIES=%s", target, dylib),
	}
}

func (p *procInject) Cleanup() error { return nil }

func init() {
	module.Register(&procInject{})
}
