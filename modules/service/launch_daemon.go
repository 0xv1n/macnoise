package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
	"howett.net/plist"
)

type svcLaunchDaemon struct {
	plistPath string
	label     string
	loaded    bool
}

func (s *svcLaunchDaemon) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_launch_daemon",
		EventTypes:  []string{"launchdaemon_create", "launchdaemon_load"},
		Description: "Creates and loads a LaunchDaemon plist in /Library/LaunchDaemons/ (requires root)",
		Category:    module.CategoryService,
		Tags:        []string{"launchdaemon", "persistence", "plist", "launchctl", "root"},
		Privileges:  module.PrivilegeRoot,
		MITRE: []module.MITRE{
			{Technique: "T1543", SubTech: ".004", Name: "Create or Modify System Process: Launch Daemon"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (s *svcLaunchDaemon) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "label", Description: "LaunchDaemon label", Type: module.ParamString, Default: "com.macnoise.testdaemon", Example: "com.corp.mydaemon"},
		{Name: "program", Description: "Program to run", Type: module.ParamPath, Default: "/usr/bin/true", Example: "/bin/sh"},
	}
}

func (s *svcLaunchDaemon) CheckPrereqs(ctx context.Context, params module.Params) error {
	return prereqs.CheckRoot()
}

func (s *svcLaunchDaemon) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	label := stampLabel(params.String("label", "com.macnoise.testdaemon"), module.RunIDFromContext(ctx))
	program := params.String("program", "/usr/bin/true")
	info := s.Info()

	daemonDir := "/Library/LaunchDaemons"
	plistPath := filepath.Join(daemonDir, label+".plist")
	s.plistPath = plistPath
	s.label = label

	plistData := map[string]any{
		"Label":            label,
		"ProgramArguments": []string{program},
		"RunAtLoad":        false,
		"KeepAlive":        false,
	}

	createEv := output.NewEvent(info, "launchdaemon_create", module.OutcomeError, module.Service(label, systemDomain, plistPath), fmt.Sprintf("creating plist at %s", plistPath))
	f, err := os.Create(plistPath)
	if err != nil {
		createEv = output.WithError(createEv, err)
		return errors.Join(err, emit(createEv))
	}
	enc := plist.NewEncoder(f)
	enc.Indent("\t")
	if err := enc.Encode(plistData); err != nil {
		_ = f.Close()
		createEv = output.WithError(createEv, err)
		return errors.Join(err, emit(createEv))
	}
	_ = f.Close()
	os.Chmod(plistPath, 0o644) //nolint:errcheck

	createEv.Outcome = module.OutcomeExecuted
	createEv.Message = fmt.Sprintf("created LaunchDaemon plist at %s", plistPath)
	createEv = output.WithDetails(createEv, map[string]any{"path": plistPath, "label": label, "program": program})
	if err := emit(createEv); err != nil {
		return err
	}

	loadEv := output.NewEvent(info, "launchdaemon_load", module.OutcomeError, module.Service(label, systemDomain, plistPath), fmt.Sprintf("bootstrapping %s into %s", label, systemDomain))
	loadCmd := exec.CommandContext(ctx, "launchctl", bootstrapArgs(systemDomain, plistPath)...)
	out, err := loadCmd.CombinedOutput()
	if err != nil {
		loadEv = output.WithError(loadEv, fmt.Errorf("%v: %s", err, out))
		return emit(loadEv)
	}
	s.loaded = true
	loadEv.Outcome = module.OutcomeExecuted
	loadEv.Message = fmt.Sprintf("bootstrapped LaunchDaemon %s into %s", label, systemDomain)
	loadEv = output.WithDetails(loadEv, map[string]any{"label": label, "plist": plistPath, "domain": systemDomain})
	return emit(loadEv)
}

func (s *svcLaunchDaemon) DryRun(params module.Params) []string {
	label := params.String("label", "com.macnoise.testdaemon")
	program := params.String("program", "/usr/bin/true")
	return []string{
		fmt.Sprintf("create /Library/LaunchDaemons/%s.plist with Program=%s (requires root)", label, program),
		launchctlCmdLine(bootstrapArgs(systemDomain, fmt.Sprintf("/Library/LaunchDaemons/%s.plist", label))),
	}
}

// Cleanup boots the daemon out before removing its plist. As with the agent, a
// bootout failure is only reported when Generate actually loaded it.
func (s *svcLaunchDaemon) Cleanup(ctx context.Context) error {
	var bootoutErr error
	if s.loaded {
		out, err := exec.CommandContext(ctx, "launchctl", bootoutArgs(systemDomain, s.label)...).CombinedOutput()
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
	module.Register(func() module.Generator { return &svcLaunchDaemon{} })
}
