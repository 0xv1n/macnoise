// Package plistmod provides telemetry modules for plist file creation and modification,
// generating file write events and defaults-system activity observed by EDR sensors.
package plistmod

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/ownership"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type plistCreate struct {
	createdFile ownership.File
	createdDirs []ownership.Directory
}

func (p *plistCreate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "plist_create",
		EventTypes:  []string{"plist_create", "plist_create_launchagent"},
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
		{Name: "output_path", Description: "Path for the created plist file", Type: module.ParamPath, Default: "/tmp/macnoise_test.plist", Example: "/tmp/test.plist"},
		{Name: "bundle_id", Description: "Bundle ID value to embed in plist", Type: module.ParamString, Default: "com.macnoise.test", Example: "com.example.app"},
		{Name: "mode", Description: "Plist mode: 'bundle' (default) writes CFBundle keys; 'launchagent' writes LaunchAgent keys", Type: module.ParamString, Default: "bundle", Example: "launchagent", Choices: []string{"bundle", "launchagent"}},
		{Name: "label", Description: "LaunchAgent Label key (used when mode=launchagent, defaults to bundle_id)", Type: module.ParamString, Example: "com.apple.coredata"},
		{Name: "program", Description: "LaunchAgent ProgramArguments first element (used when mode=launchagent)", Type: module.ParamPath, Default: "/usr/bin/true", Example: "/Library/LaunchAgents/helper"},
	}
}

func (p *plistCreate) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (p *plistCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	runID := module.RunIDFromContext(ctx)
	outPath := module.TagPath(params.String("output_path", "/tmp/macnoise_test.plist"), runID)
	bundleID := params.String("bundle_id", "com.macnoise.test")
	if runID != "" {
		bundleID += "." + runID
	}
	mode := params.String("mode", "bundle")
	info := p.Info()

	createdDirs, err := ownership.EnsureDirectories(filepath.Dir(outPath), 0o755)
	p.createdDirs = append(p.createdDirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	var plistData map[string]any
	var evAction, evMsg string

	if mode == "launchagent" {
		label := params.String("label", bundleID)
		program := params.String("program", "/usr/bin/true")
		plistData = map[string]any{
			"Label":            label,
			"ProgramArguments": []string{program},
			"RunAtLoad":        true,
			"KeepAlive":        false,
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

	ev := output.NewEvent(info, evAction, module.OutcomeError, module.File(outPath), evMsg)
	var encoded bytes.Buffer
	enc := plist.NewEncoder(&encoded)
	enc.Indent("\t")
	if err := enc.Encode(plistData); err != nil {
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	createdFile, err := ownership.CreateFile(outPath, encoded.Bytes(), 0o644)
	if err != nil {
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	p.createdFile = createdFile

	if mode == "launchagent" {
		label := params.String("label", bundleID)
		program := params.String("program", "/usr/bin/true")
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("created LaunchAgent plist at %s (label: %s, program: %s)", outPath, label, program)
		ev = output.WithDetails(ev, map[string]any{"path": outPath, "label": label, "program": program, "run_at_load": true, "format": "xml"})
	} else {
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("created plist at %s (bundle ID: %s)", outPath, bundleID)
		ev = output.WithDetails(ev, map[string]any{"path": outPath, "bundle_id": bundleID, "format": "xml"})
	}
	return emit(ev)
}

func (p *plistCreate) DryRun(params module.Params) []string {
	outPath := params.String("output_path", "/tmp/macnoise_test.plist")
	mode := params.String("mode", "bundle")
	if mode == "launchagent" {
		bundleID := params.String("bundle_id", "com.macnoise.test")
		label := params.String("label", bundleID)
		program := params.String("program", "/usr/bin/true")
		return []string{
			fmt.Sprintf("create LaunchAgent plist at %s with Label=%s ProgramArguments=[%s] RunAtLoad=true", outPath, label, program),
		}
	}
	bundleID := params.String("bundle_id", "com.macnoise.test")
	return []string{
		fmt.Sprintf("create XML plist at %s with CFBundleIdentifier=%s", outPath, bundleID),
	}
}

func (p *plistCreate) Cleanup(ctx context.Context) error {
	return errors.Join(p.createdFile.Remove(), ownership.RemoveDirectories(p.createdDirs))
}

func init() {
	module.Register(func() module.Generator { return &plistCreate{} })
}
