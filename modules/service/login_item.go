package service

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type svcLoginItem struct {
	name  string
	added bool
}

func (s *svcLoginItem) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_login_item",
		EventTypes:  []string{"login_item_add"},
		Description: "Adds a Login Item via System Events, triggering ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD",
		Category:    module.CategoryService,
		Tags:        []string{"login-item", "persistence", "btm", "osascript", "backgroundtaskmanagement"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1547", SubTech: ".015", Name: "Boot or Logon Autostart Execution: Login Items"},
		},
		Author:   "0xv1n",
		MinMacOS: "13.0",
	}
}

func (s *svcLoginItem) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "name", Description: "Login item name", Required: false, DefaultValue: "MacNoiseLoginItem", Example: "com.corp.helper"},
		{Name: "path", Description: "POSIX path the login item points at", Required: false, DefaultValue: "/usr/bin/true", Example: "/Applications/Evil.app"},
	}
}

func (s *svcLoginItem) CheckPrereqs() error { return nil }

// The AppleScript builders are shared by Generate, Cleanup, and DryRun so the
// advertised commands cannot drift from the executed ones.

func makeLoginItemScript(name, path string) string {
	return fmt.Sprintf(
		`tell application "System Events" to make login item at end with properties {name:%s, path:%s, hidden:false}`,
		appleScriptString(name), appleScriptString(path))
}

func listLoginItemsScript() string {
	return `tell application "System Events" to get the name of every login item`
}

func deleteLoginItemScript(name string) string {
	return fmt.Sprintf(
		`tell application "System Events" to delete (every login item whose name is %s)`,
		appleScriptString(name))
}

// appleScriptString renders a Go string as an AppleScript string literal,
// escaping backslashes and quotes. Without this a name or path containing a
// quote would break out of the literal and change the statement, the same
// class of bug the es_process quoting fix addressed.
func appleScriptString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// loginItemOutcome classifies an osascript run into an event outcome, so a host
// that refused or could not attempt the add is not reported as a broken tool.
//
// The osascript exit code alone cannot carry this: it exits non-zero for a TCC
// refusal, a missing GUI session, and a real macnoise fault alike. The error
// numbers System Events returns are the discriminator:
//
//   - -1743: the user has not granted Automation control of System Events, so
//     the add was refused. That refusal is a real BTM-adjacent security event.
//   - -10810: System Events could not be launched, which happens when there is
//     no GUI (Aqua) session, e.g. over ssh. Nothing was attempted, so the
//     outcome is indeterminate rather than a denial.
//   - no error: the item was added.
func loginItemOutcome(err error, combinedOutput string) module.Outcome {
	if err == nil {
		return module.OutcomeExecuted
	}
	switch {
	case strings.Contains(combinedOutput, "-1743"), strings.Contains(combinedOutput, "Not authorized"):
		return module.OutcomeDenied
	case strings.Contains(combinedOutput, "-10810"):
		return module.OutcomeIndeterminate
	default:
		return module.OutcomeError
	}
}

// parseLoginItemNames splits the comma-separated list AppleScript returns for
// "name of every login item" into individual names. AppleScript joins list
// elements with ", ", so a name containing a comma cannot be recovered from
// this output; that only affects the post-add verification, not the add
// itself.
func parseLoginItemNames(out string) []string {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	parts := strings.Split(out, ",")
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			names = append(names, p)
		}
	}
	return names
}

func (s *svcLoginItem) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	name := params.Get("name", "MacNoiseLoginItem")
	if runID := module.RunIDFromContext(ctx); runID != "" {
		name += "_" + runID
	}
	targetPath := params.Get("path", "/usr/bin/true")
	info := s.Info()
	s.name = name

	ev := output.NewEvent(info, "login_item_add", false,
		fmt.Sprintf("adding login item %q -> %s (triggers ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)", name, targetPath))
	details := map[string]any{
		"name":     name,
		"path":     targetPath,
		"es_event": "ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD",
		"method":   "osascript System Events make login item",
	}

	out, err := runOsascript(ctx, makeLoginItemScript(name, targetPath))
	outcome := loginItemOutcome(err, out)
	details["result"] = string(outcome)

	switch outcome {
	case module.OutcomeExecuted:
		s.added = true
		ev.Message = fmt.Sprintf("added login item %q -> %s (ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD)", name, targetPath)
		if present, listErr := s.loginItemPresent(ctx, name); listErr == nil {
			details["verified_present"] = present
		}
	case module.OutcomeDenied:
		ev.Message = fmt.Sprintf("login item add refused for %q: Automation control of System Events not granted", name)
	case module.OutcomeIndeterminate:
		ev.Message = fmt.Sprintf("login item add could not be attempted for %q: no GUI session to run System Events", name)
	default:
		ev.Message = fmt.Sprintf("login item add failed for %q", name)
	}

	ev = output.WithOutcome(ev, outcome, err)
	emit(output.WithDetails(ev, details))
	return nil
}

// loginItemPresent verifies the add landed rather than trusting osascript's
// exit code, the same way es_mount reads its mount point back from hdiutil.
func (s *svcLoginItem) loginItemPresent(ctx context.Context, name string) (bool, error) {
	out, err := runOsascript(ctx, listLoginItemsScript())
	if err != nil {
		return false, err
	}
	return slices.Contains(parseLoginItemNames(out), name), nil
}

func runOsascript(ctx context.Context, script string) (string, error) {
	out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (s *svcLoginItem) DryRun(params module.Params) []string {
	name := params.Get("name", "MacNoiseLoginItem")
	targetPath := params.Get("path", "/usr/bin/true")
	return []string{
		fmt.Sprintf("osascript -e '%s' -> ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD", makeLoginItemScript(name, targetPath)),
		fmt.Sprintf("osascript -e '%s'", deleteLoginItemScript(name)),
	}
}

// Cleanup removes the login item only if Generate actually added one. A run
// that was refused or could not reach a GUI session added nothing, so issuing
// the delete would report a failure for an item that never existed.
func (s *svcLoginItem) Cleanup() error {
	if !s.added || s.name == "" {
		return nil
	}
	if out, err := exec.Command("osascript", "-e", deleteLoginItemScript(s.name)).CombinedOutput(); err != nil {
		return fmt.Errorf("delete login item %q: %v: %s", s.name, err, strings.TrimSpace(string(out)))
	}
	s.added = false
	return nil
}

func init() {
	module.Register(&svcLoginItem{})
}
