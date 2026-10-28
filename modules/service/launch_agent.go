// Package service provides telemetry modules for LaunchAgent and LaunchDaemon
// persistence simulation. Modules create plist files and load them via launchctl
// to generate service installation events visible to EDR and audit frameworks.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/ownership"
	"github.com/0xv1n/macnoise/pkg/module"
)

type svcLaunchAgent struct {
	plist       ownership.File
	createdDirs []ownership.Directory
	label       string
	domain      string
	loaded      bool
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
		{Name: "label", Description: "LaunchAgent label (bundle ID style)", Type: module.ParamString, Default: "com.macnoise.testagent", Example: "com.corp.myagent"},
		{Name: "program", Description: "Program path to run", Type: module.ParamPath, Default: "/usr/bin/true", Example: "/bin/sh"},
	}
}

func (s *svcLaunchAgent) CheckPrereqs(ctx context.Context, params module.Params) error {
	_, err := resolveLaunchdUser()
	return err
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
	label := stampLabel(params.String("label", "com.macnoise.testagent"), module.RunIDFromContext(ctx))
	program := params.String("program", "/usr/bin/true")
	info := s.Info()

	target, err := resolveLaunchdUser()
	if err != nil {
		return err
	}

	agentDir := filepath.Join(target.home, "Library", "LaunchAgents")
	createdDirs, err := ownership.EnsureDirectories(agentDir, 0o755)
	s.createdDirs = append(s.createdDirs, createdDirs...)
	if err != nil {
		return fmt.Errorf("mkdir %s: %w", agentDir, err)
	}

	plistPath := filepath.Join(agentDir, label+".plist")
	s.label = label
	s.domain = guiDomain(target.uid)

	createEv := output.NewEvent(info, "launchagent_create", module.OutcomeError, module.Service(label, s.domain, plistPath), fmt.Sprintf("creating plist at %s", plistPath))
	created, err := createLaunchdPlist(plistPath, label, program)
	if err != nil {
		createEv = output.WithError(createEv, err)
		return errors.Join(err, emit(createEv))
	}
	s.plist = created

	createEv.Outcome = module.OutcomeExecuted
	createEv.Message = fmt.Sprintf("created LaunchAgent plist at %s", plistPath)
	createEv = output.WithDetails(createEv, map[string]any{"path": plistPath, "label": label, "program": program})
	if err := emit(createEv); err != nil {
		return err
	}

	loadEv := output.NewEvent(info, "launchagent_load", module.OutcomeError, module.Service(label, s.domain, plistPath), fmt.Sprintf("bootstrapping %s into %s", label, s.domain))
	loadCmd := exec.CommandContext(ctx, "launchctl", bootstrapArgs(s.domain, plistPath)...)
	out, err := loadCmd.CombinedOutput()
	if err != nil {
		loadEv = output.WithError(loadEv, fmt.Errorf("%v: %s", err, out))
		return emit(loadEv)
	}
	s.loaded = true
	loadEv.Outcome = module.OutcomeExecuted
	loadEv.Message = fmt.Sprintf("bootstrapped LaunchAgent %s into %s", label, s.domain)
	loadEv = output.WithDetails(loadEv, map[string]any{"label": label, "plist": plistPath, "domain": s.domain})
	return emit(loadEv)
}

func (s *svcLaunchAgent) DryRun(params module.Params) []string {
	label := params.String("label", "com.macnoise.testagent")
	program := params.String("program", "/usr/bin/true")
	target, err := resolveLaunchdUser()
	if err != nil {
		target = launchdUser{uid: os.Getuid(), home: "~"}
	}
	plistPath := filepath.Join(target.home, "Library", "LaunchAgents", label+".plist")
	return []string{
		fmt.Sprintf("create %s with Program=%s", plistPath, program),
		launchctlCmdLine(bootstrapArgs(guiDomain(target.uid), plistPath)),
	}
}

// Cleanup boots the agent out before removing its plist. A bootout failure is
// only reported when Generate actually loaded the agent: if the bootstrap
// never succeeded there is nothing registered to remove, and launchctl's
// failure there says nothing about whether cleanup worked. Reporting it
// anyway would mark every run on a host without a GUI session as a cleanup
// error while leaving nothing behind.
func (s *svcLaunchAgent) Cleanup(ctx context.Context) error {
	var bootoutErr error
	if s.loaded {
		out, err := exec.CommandContext(ctx, "launchctl", bootoutArgs(s.domain, s.label)...).CombinedOutput()
		if err != nil {
			bootoutErr = fmt.Errorf("launchctl bootout %s: %v: %s", s.label, err, out)
		}
	}
	return errors.Join(bootoutErr, s.plist.Remove(), ownership.RemoveDirectories(s.createdDirs))
}

func init() {
	module.Register(func() module.Generator { return &svcLaunchAgent{} })
}
