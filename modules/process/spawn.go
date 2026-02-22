// Package process provides telemetry modules for process activity simulation,
// covering process spawning, dylib injection, and signal delivery patterns
// used by macOS malware and targeted attack tooling.
package process

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procSpawn struct{}

func (p *procSpawn) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_spawn",
		Description: "Spawns a suspicious shell command chain to generate process execution telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"execution", "shell", "spawn"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1059", SubTech: ".004", Name: "Command and Scripting Interpreter: Unix Shell"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procSpawn) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "command", Description: "Shell command to execute via sh -c", Required: false, DefaultValue: "echo 'Telemetry Payload Executed'", Example: "id && whoami"},
	}
}

func (p *procSpawn) CheckPrereqs() error { return nil }

func (p *procSpawn) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	command := params.Get("command", "echo 'Telemetry Payload Executed'")
	info := p.Info()

	ev := output.NewEvent(info, "process_spawn", false, fmt.Sprintf("spawning: sh -c %q", command))
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	ev.Success = true
	ev.Message = fmt.Sprintf("process exited 0: sh -c %q", command)
	ev = output.WithDetails(ev, map[string]any{"command": command, "output": string(out)})
	emit(ev)
	return nil
}

func (p *procSpawn) DryRun(params module.Params) []string {
	command := params.Get("command", "echo 'Telemetry Payload Executed'")
	return []string{fmt.Sprintf("exec: sh -c %q", command)}
}

func (p *procSpawn) Cleanup() error { return nil }

func init() {
	module.Register(&procSpawn{})
}
