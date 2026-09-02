package plistmod

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type plistModify struct {
	domain       string
	key          string
	priorExisted bool
	priorValue   string
}

// defaultsReadOutcome is the result of classifying a `defaults read domain
// key` invocation before plistModify overwrites it.
type defaultsReadOutcome struct {
	// safe is true when Generate can trust existed/value enough to proceed:
	// either the key definitely doesn't exist yet, or it holds a value simple
	// enough to restore faithfully later.
	safe    bool
	existed bool
	value   string
}

// classifyDefaultsRead inspects the result of `defaults read domain key` and
// reports whether it is safe to overwrite the key, knowing how to restore it.
//
// `defaults read` exits non-zero both when the key genuinely does not exist
// and when some other read failure occurs. Only the well-known "does not
// exist" message is trusted as genuinely absent; any other failure is
// reported unsafe so Generate can abort instead of guessing, and Cleanup
// never has to choose between destroying or fabricating a value it never
// actually saw.
//
// A successful read is only trusted when the value is a single line with no
// defaults array/dict delimiters. `defaults read` renders array and
// dictionary values across multiple lines; blindly feeding that text back
// through `-string` on restore would corrupt rather than restore them, so
// those are reported unsafe too.
func classifyDefaultsRead(out []byte, err error) defaultsReadOutcome {
	text := strings.TrimRight(string(out), "\n")
	if err == nil {
		if isRestorableScalar(text) {
			return defaultsReadOutcome{safe: true, existed: true, value: text}
		}
		return defaultsReadOutcome{safe: false}
	}
	if strings.Contains(strings.ToLower(text), "does not exist") {
		return defaultsReadOutcome{safe: true, existed: false}
	}
	return defaultsReadOutcome{safe: false}
}

func isRestorableScalar(text string) bool {
	if strings.Contains(text, "\n") {
		return false
	}
	trimmed := strings.TrimSpace(text)
	return !strings.HasPrefix(trimmed, "(") && !strings.HasPrefix(trimmed, "{")
}

func (p *plistModify) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "plist_modify",
		Description: "Modifies a user defaults plist key via 'defaults write' to generate plist write telemetry",
		Category:    module.CategoryPlist,
		Tags:        []string{"plist", "modify", "defaults"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1543", Name: "Create or Modify System Process"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (p *plistModify) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "domain", Description: "Defaults domain to write to", Required: false, DefaultValue: "com.macnoise.test", Example: "com.apple.finder"},
		{Name: "key", Description: "Preference key to set", Required: false, DefaultValue: "MacnoiseTest", Example: "ShowHiddenFiles"},
		{Name: "value", Description: "String value to set", Required: false, DefaultValue: "true", Example: "1"},
	}
}

func (p *plistModify) CheckPrereqs() error {
	return prereqs.CheckCommand("defaults")
}

func (p *plistModify) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	domain := params.Get("domain", "com.macnoise.test")
	if runID := module.RunIDFromContext(ctx); runID != "" {
		domain += "." + runID
	}
	key := params.Get("key", "MacnoiseTest")
	value := params.Get("value", "true")
	info := p.Info()

	readEv := output.NewEvent(info, "plist_read_prior", false, fmt.Sprintf("reading prior value of %s %s", domain, key))
	readOut, readErr := exec.CommandContext(ctx, "defaults", "read", domain, key).CombinedOutput()
	outcome := classifyDefaultsRead(readOut, readErr)
	if !outcome.safe {
		readEv = output.WithError(readEv, fmt.Errorf("cannot safely determine prior value of %s %s, refusing to overwrite: %v: %s", domain, key, readErr, strings.TrimSpace(string(readOut))))
		emit(readEv)
		return fmt.Errorf("plist_modify: cannot safely determine prior value of %s %s, aborting rather than risk losing it: %w", domain, key, readErr)
	}

	p.domain = domain
	p.key = key
	p.priorExisted = outcome.existed
	p.priorValue = outcome.value

	readEv.Success = true
	if outcome.existed {
		readEv.Message = fmt.Sprintf("%s %s already set, prior value will be restored on cleanup", domain, key)
	} else {
		readEv.Message = fmt.Sprintf("%s %s not set, key will be removed on cleanup", domain, key)
	}
	emit(readEv)

	writeEv := output.NewEvent(info, "plist_modify", false, fmt.Sprintf("defaults write %s %s %s", domain, key, value))
	cmd := exec.CommandContext(ctx, "defaults", "write", domain, key, "-string", value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeEv = output.WithError(writeEv, fmt.Errorf("%v: %s", err, out))
		emit(writeEv)
		return err
	}
	writeEv.Success = true
	writeEv.Message = fmt.Sprintf("defaults write %s %s = %q", domain, key, value)
	writeEv = output.WithDetails(writeEv, map[string]any{"domain": domain, "key": key, "value": value})
	emit(writeEv)
	return nil
}

func (p *plistModify) DryRun(params module.Params) []string {
	domain := params.Get("domain", "com.macnoise.test")
	key := params.Get("key", "MacnoiseTest")
	value := params.Get("value", "true")
	return []string{
		fmt.Sprintf("defaults read %s %s (capture prior value for cleanup)", domain, key),
		fmt.Sprintf("defaults write %s %s -string %s", domain, key, value),
	}
}

func (p *plistModify) Cleanup() error {
	if p.domain == "" || p.key == "" {
		return nil
	}
	if p.priorExisted {
		out, err := exec.Command("defaults", "write", p.domain, p.key, "-string", p.priorValue).CombinedOutput()
		if err != nil {
			return fmt.Errorf("defaults write %s %s (restore prior value): %v: %s", p.domain, p.key, err, out)
		}
		return nil
	}
	out, err := exec.Command("defaults", "delete", p.domain, p.key).CombinedOutput()
	if err != nil {
		return fmt.Errorf("defaults delete %s %s: %v: %s", p.domain, p.key, err, out)
	}
	return nil
}

func init() {
	module.Register(&plistModify{})
}
