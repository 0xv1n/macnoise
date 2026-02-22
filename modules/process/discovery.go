package process

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

var defaultDiscoveryCommands = []string{
	"sw_vers",
	"system_profiler SPHardwareDataType",
	"sysctl hw.model",
	"ifconfig",
	"whoami",
	"dscl . -list /Users",
	"csrutil status",
	"fdesetup status",
}

type procDiscovery struct{}

func (p *procDiscovery) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_discovery",
		Description: "Runs macOS system reconnaissance commands to generate discovery telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"discovery", "recon", "sysinfo"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1082", Name: "System Information Discovery"},
			{Technique: "T1016", Name: "System Network Configuration Discovery"},
			{Technique: "T1033", Name: "System Owner/User Discovery"},
			{Technique: "T1518", Name: "Software Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procDiscovery) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "commands",
			Description:  "Comma-separated list of discovery commands to run",
			Required:     false,
			DefaultValue: strings.Join(defaultDiscoveryCommands, ","),
			Example:      "sw_vers,whoami",
		},
	}
}

func (p *procDiscovery) CheckPrereqs() error { return nil }

func (p *procDiscovery) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	commandsParam := params.Get("commands", strings.Join(defaultDiscoveryCommands, ","))
	commands := strings.Split(commandsParam, ",")
	info := p.Info()

	for _, raw := range commands {
		cmd := strings.TrimSpace(raw)
		if cmd == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev := output.NewEvent(info, "system_discovery", false, fmt.Sprintf("running: %s", cmd))
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil {
			ev.Success = true
			ev.Message = fmt.Sprintf("discovery command returned error: %s", cmd)
			ev = output.WithDetails(ev, map[string]any{"command": cmd, "output": string(out), "error": err.Error()})
		} else {
			ev.Success = true
			ev.Message = fmt.Sprintf("discovery command completed: %s", cmd)
			ev = output.WithDetails(ev, map[string]any{"command": cmd, "output": string(out)})
		}
		emit(ev)
	}
	return nil
}

func (p *procDiscovery) DryRun(params module.Params) []string {
	commandsParam := params.Get("commands", strings.Join(defaultDiscoveryCommands, ","))
	commands := strings.Split(commandsParam, ",")
	steps := make([]string, 0, len(commands))
	for _, cmd := range commands {
		cmd = strings.TrimSpace(cmd)
		if cmd != "" {
			steps = append(steps, fmt.Sprintf("exec: sh -c %q", cmd))
		}
	}
	return steps
}

func (p *procDiscovery) Cleanup() error { return nil }

func init() {
	module.Register(&procDiscovery{})
}
