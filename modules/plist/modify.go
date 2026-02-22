package plistmod

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type plistModify struct {
	domain string
	key    string
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
	key := params.Get("key", "MacnoiseTest")
	value := params.Get("value", "true")
	info := p.Info()

	p.domain = domain
	p.key = key

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
		fmt.Sprintf("defaults write %s %s -string %s", domain, key, value),
	}
}

func (p *plistModify) Cleanup() error {
	if p.domain == "" || p.key == "" {
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
