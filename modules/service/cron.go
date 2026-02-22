package service

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type svcCron struct {
	addedEntry string
}

func (s *svcCron) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_cron",
		Description: "Lists and appends a cron job entry to simulate cron-based persistence",
		Category:    module.CategoryService,
		Tags:        []string{"cron", "persistence", "scheduled-task"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1053", SubTech: ".003", Name: "Scheduled Task/Job: Cron"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (s *svcCron) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "schedule", Description: "Cron schedule expression", Required: false, DefaultValue: "*/5 * * * *", Example: "@hourly"},
		{Name: "command", Description: "Command for the cron job", Required: false, DefaultValue: "/usr/bin/true", Example: "/bin/sh -c 'echo test'"},
	}
}

func (s *svcCron) CheckPrereqs() error { return nil }

func (s *svcCron) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	schedule := params.Get("schedule", "*/5 * * * *")
	command := params.Get("command", "/usr/bin/true")
	info := s.Info()

	marker := "# macnoise"
	entry := fmt.Sprintf("%s %s %s", schedule, command, marker)

	listEv := output.NewEvent(info, "cron_job_list", false, "listing current crontab entries")
	listOut, listErr := exec.CommandContext(ctx, "crontab", "-l").CombinedOutput()
	existing := ""
	if listErr != nil {
		listEv.Success = true
		listEv.Message = "no existing crontab (empty crontab)"
		listEv = output.WithDetails(listEv, map[string]any{"entries": ""})
	} else {
		existing = string(listOut)
		lineCount := len(strings.Split(strings.TrimSpace(existing), "\n"))
		listEv.Success = true
		listEv.Message = fmt.Sprintf("retrieved crontab (%d lines)", lineCount)
		listEv = output.WithDetails(listEv, map[string]any{"entries": existing})
	}
	emit(listEv)

	createEv := output.NewEvent(info, "cron_job_create", false, fmt.Sprintf("adding cron entry: %s", entry))
	newCrontab := strings.TrimRight(existing, "\n") + "\n" + entry + "\n"
	installCmd := exec.CommandContext(ctx, "crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if out, err := installCmd.CombinedOutput(); err != nil {
		createEv = output.WithError(createEv, fmt.Errorf("%v: %s", err, out))
	} else {
		s.addedEntry = entry
		createEv.Success = true
		createEv.Message = fmt.Sprintf("cron job installed: %s", entry)
		createEv = output.WithDetails(createEv, map[string]any{
			"schedule": schedule,
			"command":  command,
			"entry":    entry,
		})
	}
	emit(createEv)

	return nil
}

func (s *svcCron) DryRun(params module.Params) []string {
	schedule := params.Get("schedule", "*/5 * * * *")
	command := params.Get("command", "/usr/bin/true")
	return []string{
		"crontab -l",
		fmt.Sprintf("crontab -: append \"%s %s # macnoise\"", schedule, command),
	}
}

func (s *svcCron) Cleanup() error {
	if s.addedEntry == "" {
		return nil
	}
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		s.addedEntry = ""
		return nil
	}
	lines := strings.Split(string(out), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != strings.TrimSpace(s.addedEntry) {
			filtered = append(filtered, line)
		}
	}
	newCrontab := strings.Join(filtered, "\n")
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCrontab)
	s.addedEntry = ""
	return cmd.Run()
}

func init() {
	module.Register(&svcCron{})
}
