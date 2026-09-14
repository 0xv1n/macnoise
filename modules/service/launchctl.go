package service

import (
	"fmt"
	"strings"
)

// systemDomain is the launchd domain that holds LaunchDaemons.
const systemDomain = "system"

type launchdUser struct {
	uid  int
	home string
}

func selectLaunchdUser(process, console launchdUser) (launchdUser, error) {
	if process.uid != 0 {
		return process, nil
	}
	if console.uid <= 0 || console.home == "" {
		return launchdUser{}, fmt.Errorf("no logged-in GUI user is available for a LaunchAgent")
	}
	return console, nil
}

// guiDomain returns the launchd domain that holds one user's LaunchAgents.
func guiDomain(uid int) string {
	return fmt.Sprintf("gui/%d", uid)
}

// bootstrapArgs builds the launchctl argv that registers plistPath in domain.
//
// This replaces `launchctl load`, which Apple documents as legacy. The
// distinction matters for a telemetry generator specifically: detection
// content increasingly keys on the `bootstrap` subcommand, so emitting the
// legacy form generates activity that modern rules are not watching for.
func bootstrapArgs(domain, plistPath string) []string {
	return []string{"bootstrap", domain, plistPath}
}

// bootoutArgs builds the launchctl argv that removes label from domain. The
// service-target form is used rather than the plist path so that unloading
// still works once the plist has been deleted.
func bootoutArgs(domain, label string) []string {
	return []string{"bootout", domain + "/" + label}
}

// launchctlCmdLine renders argv as the command line a dry-run advertises.
// DryRun builds its description from the same argv the module executes, so the
// two cannot drift into advertising one subcommand while running another.
func launchctlCmdLine(args []string) string {
	return "launchctl " + strings.Join(args, " ")
}
