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
		EventTypes:  []string{"cron_job_list", "cron_job_create"},
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

// noCrontabMarker is the substring `crontab -l` prints to stderr when a user
// genuinely has no crontab yet (e.g. "crontab: no crontab for alice"). It is
// the only listing failure treated as safe to overwrite; see
// classifyCrontabList for why every other failure is not.
const noCrontabMarker = "no crontab for"

// classifyCrontabList inspects the result of `crontab -l` and reports whether
// it is safe to treat the user's crontab as known (existing, possibly empty).
//
// `crontab -l` exits non-zero both when the user genuinely has no crontab yet
// and when access is denied - for example when the calling terminal lacks
// Full Disk Access on modern macOS, or another read failure occurs. Treating
// every listing failure as "empty crontab" and overwriting it, as this
// function's caller previously did, risks silently destroying a real
// crontab that macnoise was simply unable to read. Only the well-known
// "no crontab for <user>" message is trusted as genuinely empty; any other
// failure is reported unsafe so the caller can abort instead of guessing.
func classifyCrontabList(out []byte, err error) (existing string, safe bool) {
	if err == nil {
		return string(out), true
	}
	if strings.Contains(strings.ToLower(string(out)), noCrontabMarker) {
		return "", true
	}
	return "", false
}

// cronMarker returns the trailing comment tagging the entry as macnoise's,
// folding the run ID in when set so a consumer can correlate the crontab
// change back to the run.
func cronMarker(runID string) string {
	if runID == "" {
		return "# macnoise"
	}
	return "# macnoise " + runID
}

func (s *svcCron) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	schedule := params.Get("schedule", "*/5 * * * *")
	command := params.Get("command", "/usr/bin/true")
	info := s.Info()

	marker := cronMarker(module.RunIDFromContext(ctx))
	entry := fmt.Sprintf("%s %s %s", schedule, command, marker)

	listEv := output.NewEvent(info, "cron_job_list", false, "listing current crontab entries")
	listOut, listErr := exec.CommandContext(ctx, "crontab", "-l").CombinedOutput()
	existing, safe := classifyCrontabList(listOut, listErr)
	if !safe {
		listEv = output.WithError(listEv, fmt.Errorf("crontab -l failed without reporting an empty crontab, refusing to overwrite: %v: %s", listErr, strings.TrimSpace(string(listOut))))
		emit(listEv)
		return fmt.Errorf("svc_cron: cannot safely determine existing crontab contents, aborting rather than risk overwriting it: %w", listErr)
	}

	if listErr != nil {
		listEv.Success = true
		listEv.Message = "no existing crontab (empty crontab)"
		listEv = output.WithDetails(listEv, map[string]any{"entries": ""})
	} else {
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
	out, err := exec.Command("crontab", "-l").CombinedOutput()
	existing, safe := classifyCrontabList(out, err)
	if !safe {
		// Leave addedEntry set: we don't know whether our entry is still
		// installed, so a caller retrying Cleanup should try again rather
		// than have this silently reported as done.
		return fmt.Errorf("svc_cron: cleanup cannot safely list crontab, entry %q may still be installed: %v: %s", s.addedEntry, err, strings.TrimSpace(string(out)))
	}

	lines := strings.Split(existing, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != strings.TrimSpace(s.addedEntry) {
			filtered = append(filtered, line)
		}
	}
	newCrontab := strings.Join(filtered, "\n")
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCrontab)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("svc_cron: failed to reinstall filtered crontab during cleanup: %w", err)
	}
	s.addedEntry = ""
	return nil
}

func init() {
	module.Register(&svcCron{})
}
