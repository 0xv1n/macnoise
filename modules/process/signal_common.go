package process

import (
	"context"
	"fmt"
	"runtime"

	"github.com/0xv1n/macnoise/pkg/module"
)

type procSignal struct{}

func (p *procSignal) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_signal",
		EventTypes:  []string{"process_fork", "signal_send"},
		Description: "Forks a process then sends signals (SIGTERM, SIGSTOP, SIGCONT) to generate signal telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"signal", "process", "fork"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1106", Name: "Native API"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procSignal) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target_command", Description: "Command to spawn as signal target", Required: false, DefaultValue: "sleep 30", Example: "sleep 60"},
	}
}

func (p *procSignal) CheckPrereqs(ctx context.Context, params module.Params) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("proc_signal is only supported on macOS")
	}
	return nil
}

func (p *procSignal) DryRun(params module.Params) []string {
	targetCmd := params.Get("target_command", "sleep 30")
	return []string{
		fmt.Sprintf("fork: sh -c %q", targetCmd),
		"send SIGSTOP, SIGCONT, SIGTERM to forked PID",
	}
}

func (p *procSignal) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &procSignal{} })
}
