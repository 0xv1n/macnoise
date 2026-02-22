//go:build darwin

package process

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procOsascript struct{}

func (p *procOsascript) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_osascript",
		Description: "Executes AppleScript or JXA via osascript to generate scripting interpreter telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"osascript", "applescript", "jxa", "execution"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1059", SubTech: ".002", Name: "Command and Scripting Interpreter: AppleScript"},
			{Technique: "T1059", SubTech: ".007", Name: "Command and Scripting Interpreter: JavaScript"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procOsascript) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "script",
			Description:  "AppleScript or JXA code to execute",
			Required:     false,
			DefaultValue: `display notification "macnoise telemetry" with title "MacNoise"`,
			Example:      `do shell script "id"`,
		},
		{
			Name:         "language",
			Description:  "Script language: AppleScript or JavaScript",
			Required:     false,
			DefaultValue: "AppleScript",
			Example:      "JavaScript",
		},
	}
}

func (p *procOsascript) CheckPrereqs() error { return nil }

func (p *procOsascript) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	script := params.Get("script", `display notification "macnoise telemetry" with title "MacNoise"`)
	language := params.Get("language", "AppleScript")
	info := p.Info()

	ev := output.NewEvent(info, "osascript_exec", false, fmt.Sprintf("executing %s via osascript", language))
	out, err := exec.CommandContext(ctx, "osascript", "-l", language, "-e", script).CombinedOutput()
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("osascript returned error (telemetry generated): %v", err)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": string(out), "error": err.Error()})
	} else {
		ev.Success = true
		ev.Message = fmt.Sprintf("osascript executed %s successfully", language)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": string(out)})
	}
	emit(ev)
	return nil
}

func (p *procOsascript) DryRun(params module.Params) []string {
	script := params.Get("script", `display notification "macnoise telemetry" with title "MacNoise"`)
	language := params.Get("language", "AppleScript")
	return []string{fmt.Sprintf("osascript -l %s -e %q", language, script)}
}

func (p *procOsascript) Cleanup() error { return nil }

func init() {
	module.Register(&procOsascript{})
}
