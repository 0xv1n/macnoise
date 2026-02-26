// Package plistmod provides telemetry modules for plist file creation and modification,
// generating file write events and defaults-system activity observed by EDR sensors.
package plistmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type plistCreate struct {
	createdPath string
}

func (p *plistCreate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "plist_create",
		Description: "Creates a plist file using howett.net/plist to generate plist write telemetry",
		Category:    module.CategoryPlist,
		Tags:        []string{"plist", "create", "file"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1543", Name: "Create or Modify System Process"},
			{Technique: "T1543", SubTech: ".001", Name: "Create or Modify System Process: Launch Agent"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (p *plistCreate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "output_path", Description: "Path for the created plist file", Required: false, DefaultValue: "/tmp/macnoise_test.plist", Example: "/tmp/test.plist"},
		{Name: "bundle_id", Description: "Bundle ID value to embed in plist", Required: false, DefaultValue: "com.macnoise.test", Example: "com.example.app"},
		{Name: "mode", Description: "Plist mode: 'bundle' (default) writes CFBundle keys; 'launchagent' writes LaunchAgent keys", Required: false, DefaultValue: "bundle", Example: "launchagent"},
		{Name: "label", Description: "LaunchAgent Label key (used when mode=launchagent, defaults to bundle_id)", Required: false, DefaultValue: "", Example: "com.apple.coredata"},
		{Name: "program", Description: "LaunchAgent ProgramArguments first element (used when mode=launchagent)", Required: false, DefaultValue: "/usr/bin/true", Example: "/Library/LaunchAgents/helper"},
	}
}

func (p *plistCreate) CheckPrereqs() error { return nil }

func (p *plistCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	outPath := params.Get("output_path", "/tmp/macnoise_test.plist")
	bundleID := params.Get("bundle_id", "com.macnoise.test")
	mode := params.Get("mode", "bundle")
	info := p.Info()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	var plistData map[string]any
	var evAction, evMsg string

	if mode == "launchagent" {
		label := params.Get("label", bundleID)
		program := params.Get("program", "/usr/bin/true")
		plistData = map[string]any{
			"Label":             label,
			"ProgramArguments":  []string{program},
			"RunAtLoad":         true,
			"KeepAlive":         false,
		}
		evAction = "plist_create_launchagent"
		evMsg = fmt.Sprintf("creating LaunchAgent plist at %s (label: %s)", outPath, label)
	} else {
		plistData = map[string]any{
			"CFBundleIdentifier": bundleID,
			"CFBundleVersion":    "1.0",
			"MacnoiseGenerated":  true,
			"GeneratedBy":        "MacNoise",
		}
		evAction = "plist_create"
		evMsg = fmt.Sprintf("creating plist at %s", outPath)
	}

	ev := output.NewEvent(info, evAction, false, evMsg)
	f, err := os.Create(outPath)
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	enc := plist.NewEncoder(f)
	enc.Indent("\t")
	if err := enc.Encode(plistData); err != nil {
		_ = f.Close()
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	_ = f.Close()
	p.createdPath = outPath

	if mode == "launchagent" {
		label := params.Get("label", bundleID)
		program := params.Get("program", "/usr/bin/true")
		ev.Success = true
		ev.Message = fmt.Sprintf("created LaunchAgent plist at %s (label: %s, program: %s)", outPath, label, program)
		ev = output.WithDetails(ev, map[string]any{"path": outPath, "label": label, "program": program, "run_at_load": true, "format": "xml"})
	} else {
		ev.Success = true
		ev.Message = fmt.Sprintf("created plist at %s (bundle ID: %s)", outPath, bundleID)
		ev = output.WithDetails(ev, map[string]any{"path": outPath, "bundle_id": bundleID, "format": "xml"})
	}
	emit(ev)
	return nil
}

func (p *plistCreate) DryRun(params module.Params) []string {
	outPath := params.Get("output_path", "/tmp/macnoise_test.plist")
	mode := params.Get("mode", "bundle")
	if mode == "launchagent" {
		bundleID := params.Get("bundle_id", "com.macnoise.test")
		label := params.Get("label", bundleID)
		program := params.Get("program", "/usr/bin/true")
		return []string{
			fmt.Sprintf("create LaunchAgent plist at %s with Label=%s ProgramArguments=[%s] RunAtLoad=true", outPath, label, program),
		}
	}
	bundleID := params.Get("bundle_id", "com.macnoise.test")
	return []string{
		fmt.Sprintf("create XML plist at %s with CFBundleIdentifier=%s", outPath, bundleID),
	}
}

func (p *plistCreate) Cleanup() error {
	if p.createdPath != "" {
		return os.Remove(p.createdPath)
	}
	return nil
}

func init() {
	module.Register(&plistCreate{})
}
