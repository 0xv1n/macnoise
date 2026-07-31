//go:build darwin

package process

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procOsascript struct{}

// redactedOutput replaces the captured result of a script that solicited
// hidden/masked input.
const redactedOutput = "[redacted: script requested hidden input via osascript]"

// sanitizeOsascriptOutput redacts osascript's captured stdout when script
// solicited hidden/masked input: AppleScript's `display dialog ... with
// hidden answer`, or JXA's equivalent `hiddenAnswer` option.
//
// osascript prints the dialog's result record to stdout verbatim, including
// literally what was typed. Capturing that into telemetry/audit output would
// persist whatever an operator typed into what looks like a real system
// password prompt, in cleartext, on disk - with no benefit, since the typed
// value itself carries no detection-relevant signal. The command line and
// script source (what a detection rule actually keys on) are left untouched;
// only the captured runtime result is redacted.
func sanitizeOsascriptOutput(script, out string) string {
	normalized := strings.ToLower(strings.ReplaceAll(script, " ", ""))
	if strings.Contains(normalized, "hiddenanswer") {
		return redactedOutput
	}
	return out
}

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
	safeOutput := sanitizeOsascriptOutput(script, string(out))
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("osascript returned error (telemetry generated): %v", err)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": safeOutput, "error": err.Error()})
	} else {
		ev.Success = true
		ev.Message = fmt.Sprintf("osascript executed %s successfully", language)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": safeOutput})
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
