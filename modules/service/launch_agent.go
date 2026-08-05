// Package service provides telemetry modules for LaunchAgent and LaunchDaemon
// persistence simulation. Modules create plist files and load them via launchctl
// to generate service installation events visible to EDR and audit frameworks.
package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type svcLaunchAgent struct {
	plistPath string
	label     string
}

func (s *svcLaunchAgent) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_launch_agent",
		Description: "Creates and loads a LaunchAgent plist in ~/Library/LaunchAgents/ for persistence telemetry",
		Category:    module.CategoryService,
		Tags:        []string{"launchagent", "persistence", "plist", "launchctl"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1543", SubTech: ".001", Name: "Create or Modify System Process: Launch Agent"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (s *svcLaunchAgent) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "label", Description: "LaunchAgent label (bundle ID style)", Required: false, DefaultValue: "com.macnoise.testagent", Example: "com.corp.myagent"},
		{Name: "program", Description: "Program path to run", Required: false, DefaultValue: "/usr/bin/true", Example: "/bin/sh"},
	}
}

func (s *svcLaunchAgent) CheckPrereqs() error {
	return nil
}

func (s *svcLaunchAgent) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	label := params.Get("label", "com.macnoise.testagent")
	program := params.Get("program", "/usr/bin/true")
	info := s.Info()

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home dir: %w", err)
	}

	agentDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", agentDir, err)
	}

	plistPath := filepath.Join(agentDir, label+".plist")
	s.plistPath = plistPath
	s.label = label

	plistData := map[string]any{
		"Label":            label,
		"ProgramArguments": []string{program},
		"RunAtLoad":        false,
		"KeepAlive":        false,
	}

	createEv := output.NewEvent(info, "launchagent_create", false, fmt.Sprintf("creating plist at %s", plistPath))
	f, err := os.Create(plistPath)
	if err != nil {
		createEv = output.WithError(createEv, err)
		emit(createEv)
		return err
	}
	enc := plist.NewEncoder(f)
	enc.Indent("\t")
	if err := enc.Encode(plistData); err != nil {
		_ = f.Close()
		createEv = output.WithError(createEv, err)
		emit(createEv)
		return err
	}
	_ = f.Close()

	createEv.Success = true
	createEv.Message = fmt.Sprintf("created LaunchAgent plist at %s", plistPath)
	createEv = output.WithDetails(createEv, map[string]any{"path": plistPath, "label": label, "program": program})
	emit(createEv)

	loadEv := output.NewEvent(info, "launchagent_load", false, fmt.Sprintf("loading %s via launchctl", label))
	loadCmd := exec.CommandContext(ctx, "launchctl", "load", plistPath)
	out, err := loadCmd.CombinedOutput()
	if err != nil {
		loadEv = output.WithError(loadEv, fmt.Errorf("%v: %s", err, out))
		emit(loadEv)
		return nil
	}
	loadEv.Success = true
	loadEv.Message = fmt.Sprintf("loaded LaunchAgent %s", label)
	loadEv = output.WithDetails(loadEv, map[string]any{"label": label, "plist": plistPath})
	emit(loadEv)

	return nil
}

func (s *svcLaunchAgent) DryRun(params module.Params) []string {
	label := params.Get("label", "com.macnoise.testagent")
	program := params.Get("program", "/usr/bin/true")
	return []string{
		fmt.Sprintf("create ~/Library/LaunchAgents/%s.plist with Program=%s", label, program),
		fmt.Sprintf("launchctl load ~/Library/LaunchAgents/%s.plist", label),
	}
}

func (s *svcLaunchAgent) Cleanup() error {
	if s.label != "" {
		exec.Command("launchctl", "unload", s.plistPath).Run() //nolint:errcheck
	}
	if s.plistPath != "" {
		return os.Remove(s.plistPath)
	}
	return nil
}

func init() {
	module.Register(&svcLaunchAgent{})
}
