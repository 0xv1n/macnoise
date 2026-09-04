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
	loaded    bool
}

func (s *svcLaunchAgent) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_launch_agent",
		EventTypes:  []string{"launchagent_create", "launchagent_load"},
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

// stampLabel appends the run ID as a trailing reverse-DNS component so the
// plist filename, Label key, and launchctl service target all carry it,
// letting a consumer correlate the persistence back to the run.
func stampLabel(label, runID string) string {
	if runID == "" {
		return label
	}
	return label + "." + runID
}

func (s *svcLaunchAgent) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	label := stampLabel(params.Get("label", "com.macnoise.testagent"), module.RunIDFromContext(ctx))
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

	domain := guiDomain()
	loadEv := output.NewEvent(info, "launchagent_load", false, fmt.Sprintf("bootstrapping %s into %s", label, domain))
	loadCmd := exec.CommandContext(ctx, "launchctl", bootstrapArgs(domain, plistPath)...)
	out, err := loadCmd.CombinedOutput()
	if err != nil {
		loadEv = output.WithError(loadEv, fmt.Errorf("%v: %s", err, out))
		emit(loadEv)
		return nil
	}
	s.loaded = true
	loadEv.Success = true
	loadEv.Message = fmt.Sprintf("bootstrapped LaunchAgent %s into %s", label, domain)
	loadEv = output.WithDetails(loadEv, map[string]any{"label": label, "plist": plistPath, "domain": domain})
	emit(loadEv)

	return nil
}

func (s *svcLaunchAgent) DryRun(params module.Params) []string {
	label := params.Get("label", "com.macnoise.testagent")
	program := params.Get("program", "/usr/bin/true")
	plistPath := fmt.Sprintf("~/Library/LaunchAgents/%s.plist", label)
	return []string{
		fmt.Sprintf("create %s with Program=%s", plistPath, program),
		launchctlCmdLine(bootstrapArgs(guiDomain(), plistPath)),
	}
}

// Cleanup boots the agent out before removing its plist. A bootout failure is
// only reported when Generate actually loaded the agent: if the bootstrap
// never succeeded there is nothing registered to remove, and launchctl's
// failure there says nothing about whether cleanup worked. Reporting it
// anyway would mark every run on a host without a GUI session as a cleanup
// error while leaving nothing behind.
func (s *svcLaunchAgent) Cleanup() error {
	var bootoutErr error
	if s.loaded {
		out, err := exec.Command("launchctl", bootoutArgs(guiDomain(), s.label)...).CombinedOutput()
		if err != nil {
			bootoutErr = fmt.Errorf("launchctl bootout %s: %v: %s", s.label, err, out)
		}
	}
	if s.plistPath != "" {
		if err := os.Remove(s.plistPath); err != nil {
			return err
		}
	}
	return bootoutErr
}

func init() {
	module.Register(&svcLaunchAgent{})
}
