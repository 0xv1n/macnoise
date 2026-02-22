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
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (p *plistCreate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "output_path", Description: "Path for the created plist file", Required: false, DefaultValue: "/tmp/macnoise_test.plist", Example: "/tmp/test.plist"},
		{Name: "bundle_id", Description: "Bundle ID value to embed in plist", Required: false, DefaultValue: "com.macnoise.test", Example: "com.example.app"},
	}
}

func (p *plistCreate) CheckPrereqs() error { return nil }

func (p *plistCreate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	outPath := params.Get("output_path", "/tmp/macnoise_test.plist")
	bundleID := params.Get("bundle_id", "com.macnoise.test")
	info := p.Info()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	plistData := map[string]any{
		"CFBundleIdentifier": bundleID,
		"CFBundleVersion":    "1.0",
		"MacnoiseGenerated":  true,
		"GeneratedBy":        "MacNoise",
	}

	ev := output.NewEvent(info, "plist_create", false, fmt.Sprintf("creating plist at %s", outPath))
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

	ev.Success = true
	ev.Message = fmt.Sprintf("created plist at %s (bundle ID: %s)", outPath, bundleID)
	ev = output.WithDetails(ev, map[string]any{"path": outPath, "bundle_id": bundleID, "format": "xml"})
	emit(ev)
	return nil
}

func (p *plistCreate) DryRun(params module.Params) []string {
	outPath := params.Get("output_path", "/tmp/macnoise_test.plist")
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
