package process

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
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
		EventTypes:  []string{"osascript_exec"},
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
			Name:        "script",
			Description: "AppleScript or JXA code to execute",
			Type:        module.ParamString,
			Default:     `display notification "macnoise telemetry" with title "MacNoise"`,
			Example:     `do shell script "id"`,
		},
		{
			Name:        "language",
			Description: "Script language: AppleScript or JavaScript",
			Type:        module.ParamString,
			Default:     "AppleScript",
			Example:     "JavaScript",
			Choices:     []string{"AppleScript", "JavaScript"},
		},
	}
}

func (p *procOsascript) CheckPrereqs(ctx context.Context, params module.Params) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("proc_osascript is only supported on macOS")
	}
	return nil
}

// stampScript appends the run ID as a language-appropriate comment so it lands
// in the osascript argv (what detection keys on) without altering execution.
func stampScript(script, language, runID string) string {
	if runID == "" {
		return script
	}
	comment := "-- mn:" + runID
	if strings.EqualFold(language, "JavaScript") {
		comment = "// mn:" + runID
	}
	return script + "\n" + comment
}

func (p *procOsascript) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	language := params.String("language", "AppleScript")
	script := stampScript(params.String("script", `display notification "macnoise telemetry" with title "MacNoise"`), language, module.RunIDFromContext(ctx))
	info := p.Info()

	ev := output.NewEvent(info, "osascript_exec", module.OutcomeError, module.Process("osascript", "/usr/bin/osascript", script, 0), fmt.Sprintf("executing %s via osascript", language))
	out, err := exec.CommandContext(ctx, "osascript", "-l", language, "-e", script).CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	safeOutput := sanitizeOsascriptOutput(script, string(out))
	if err != nil {
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("osascript returned error (telemetry generated): %v", err)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": safeOutput, "error": err.Error()})
	} else {
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("osascript executed %s successfully", language)
		ev = output.WithDetails(ev, map[string]any{"language": language, "script": script, "output": safeOutput})
	}
	return emit(ev)
}

func (p *procOsascript) DryRun(params module.Params) []string {
	script := params.String("script", `display notification "macnoise telemetry" with title "MacNoise"`)
	language := params.String("language", "AppleScript")
	return []string{fmt.Sprintf("osascript -l %s -e %q", language, script)}
}

func (p *procOsascript) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &procOsascript{} })
}
