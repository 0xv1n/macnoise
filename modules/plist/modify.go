package plistmod

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type plistModify struct {
	domain       string
	key          string
	priorExisted bool
	priorValue   any
	writtenValue string
	mutated      bool
}

// defaultsReadOutcome is the result of classifying a `defaults read domain
// key` invocation before plistModify overwrites it.
type defaultsReadOutcome struct {
	safe    bool
	existed bool
}

// classifyDefaultsRead inspects the result of `defaults read domain key` and
// reports whether the key definitely exists or is definitely absent.
//
// `defaults read` exits non-zero both when the key genuinely does not exist
// and when some other read failure occurs. Only the well-known "does not
// exist" message is trusted as genuinely absent; any other failure is
// reported unsafe so Generate can abort instead of guessing, and Cleanup
// never has to choose between destroying or fabricating a value it never
// actually saw. Existing values are captured from an exported plist so their
// type and nested structure can be restored faithfully.
func classifyDefaultsRead(out []byte, err error) defaultsReadOutcome {
	if err == nil {
		return defaultsReadOutcome{safe: true, existed: true}
	}
	text := strings.TrimRight(string(out), "\n")
	if strings.Contains(strings.ToLower(text), "does not exist") {
		return defaultsReadOutcome{safe: true, existed: false}
	}
	return defaultsReadOutcome{safe: false}
}

func (p *plistModify) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "plist_modify",
		EventTypes:  []string{"plist_read_prior", "plist_modify"},
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
		{Name: "domain", Description: "Defaults domain to write to", Type: module.ParamString, Default: "com.macnoise.test", Example: "com.apple.finder"},
		{Name: "key", Description: "Preference key to set", Type: module.ParamString, Default: "MacnoiseTest", Example: "ShowHiddenFiles"},
		{Name: "value", Description: "String value to set", Type: module.ParamString, Default: "true", Example: "1"},
	}
}

func (p *plistModify) CheckPrereqs(ctx context.Context, params module.Params) error {
	return prereqs.CheckCommand("defaults")
}

func (p *plistModify) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	domain := params.String("domain", "com.macnoise.test")
	if runID := module.RunIDFromContext(ctx); runID != "" {
		domain += "." + runID
	}
	key := params.String("key", "MacnoiseTest")
	value := params.String("value", "true")
	info := p.Info()

	readEv := output.NewEvent(info, "plist_read_prior", module.OutcomeError, module.Resource("preference", domain+":"+key, ""), fmt.Sprintf("reading prior value of %s %s", domain, key))
	readOut, readErr := exec.CommandContext(ctx, "defaults", "read", domain, key).CombinedOutput()
	outcome := classifyDefaultsRead(readOut, readErr)
	if !outcome.safe {
		readEv = output.WithError(readEv, fmt.Errorf("cannot safely determine prior value of %s %s, refusing to overwrite: %v: %s", domain, key, readErr, strings.TrimSpace(string(readOut))))
		return errors.Join(
			fmt.Errorf("plist_modify: cannot safely determine prior value of %s %s, aborting rather than risk losing it: %w", domain, key, readErr),
			emit(readEv),
		)
	}
	var priorValue any
	if outcome.existed {
		priorDomain, err := exportDefaultsDomain(ctx, domain)
		if err != nil {
			readEv = output.WithError(readEv, fmt.Errorf("export prior defaults domain %s: %w", domain, err))
			return errors.Join(err, emit(readEv))
		}
		var ok bool
		priorValue, ok = priorDomain[key]
		if !ok {
			err := fmt.Errorf("defaults export %s did not contain key %q returned by defaults read", domain, key)
			readEv = output.WithError(readEv, err)
			return errors.Join(err, emit(readEv))
		}
	}

	p.domain = domain
	p.key = key
	p.priorExisted = outcome.existed
	p.priorValue = priorValue
	p.writtenValue = value

	readEv.Outcome = module.OutcomeExecuted
	if outcome.existed {
		readEv.Message = fmt.Sprintf("%s %s already set, prior value will be restored on cleanup", domain, key)
	} else {
		readEv.Message = fmt.Sprintf("%s %s not set, key will be removed on cleanup", domain, key)
	}
	if err := emit(readEv); err != nil {
		return err
	}

	writeEv := output.NewEvent(info, "plist_modify", module.OutcomeError, module.Resource("preference", domain+":"+key, ""), fmt.Sprintf("defaults write %s %s %s", domain, key, value))
	cmd := exec.CommandContext(ctx, "defaults", "write", domain, key, "-string", value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeEv = output.WithError(writeEv, fmt.Errorf("%v: %s", err, out))
		return errors.Join(err, emit(writeEv))
	}
	p.mutated = true
	writeEv.Outcome = module.OutcomeExecuted
	writeEv.Message = fmt.Sprintf("defaults write %s %s = %q", domain, key, value)
	writeEv = output.WithDetails(writeEv, map[string]any{"domain": domain, "key": key, "value": value})
	return emit(writeEv)
}

func (p *plistModify) DryRun(params module.Params) []string {
	domain := params.String("domain", "com.macnoise.test")
	key := params.String("key", "MacnoiseTest")
	value := params.String("value", "true")
	return []string{
		fmt.Sprintf("defaults read %s %s (capture prior value for cleanup)", domain, key),
		fmt.Sprintf("defaults write %s %s -string %s", domain, key, value),
	}
}

func (p *plistModify) Cleanup(ctx context.Context) error {
	if !p.mutated {
		return nil
	}
	current, err := exportDefaultsDomain(ctx, p.domain)
	if err != nil {
		return fmt.Errorf("export defaults domain %s for cleanup: %w", p.domain, err)
	}
	if !p.priorExisted {
		if err := checkWrittenPreference(current, p.key, p.writtenValue); err != nil {
			return fmt.Errorf("plist_modify cleanup conflict for %s %s: %w", p.domain, p.key, err)
		}
		out, err := exec.CommandContext(ctx, "defaults", "delete", p.domain, p.key).CombinedOutput()
		if err != nil {
			return fmt.Errorf("defaults delete %s %s: %v: %s", p.domain, p.key, err, out)
		}
		p.mutated = false
		return nil
	}
	if err := restorePreferenceValue(current, p.key, p.writtenValue, p.priorValue); err != nil {
		return fmt.Errorf("plist_modify cleanup conflict for %s %s: %w", p.domain, p.key, err)
	}
	encoded, err := plist.Marshal(current, plist.XMLFormat)
	if err != nil {
		return fmt.Errorf("encode defaults domain %s for cleanup: %w", p.domain, err)
	}
	cmd := exec.CommandContext(ctx, "defaults", "import", p.domain, "-")
	cmd.Stdin = bytes.NewReader(encoded)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("defaults import %s (restore prior value): %v: %s", p.domain, err, out)
	}
	p.mutated = false
	return nil
}

func exportDefaultsDomain(ctx context.Context, domain string) (map[string]any, error) {
	out, err := exec.CommandContext(ctx, "defaults", "export", domain, "-").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("defaults export %s: %v: %s", domain, err, out)
	}
	var decoded map[string]any
	if err := plist.NewDecoder(bytes.NewReader(out)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode defaults export %s: %w", domain, err)
	}
	return decoded, nil
}

func restorePreferenceValue(current map[string]any, key, written string, prior any) error {
	if err := checkWrittenPreference(current, key, written); err != nil {
		return err
	}
	current[key] = prior
	return nil
}

func checkWrittenPreference(current map[string]any, key, written string) error {
	value, exists := current[key]
	if !exists {
		return fmt.Errorf("owned key is missing")
	}
	text, ok := value.(string)
	if !ok || text != written {
		return fmt.Errorf("owned key changed from %q to %#v", written, value)
	}
	return nil
}

func init() {
	module.Register(func() module.Generator { return &plistModify{} })
}
