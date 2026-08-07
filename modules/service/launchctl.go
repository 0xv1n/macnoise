package service

import (
	"fmt"
	"os"
	"strings"
)

// systemDomain is the launchd domain that holds LaunchDaemons.
const systemDomain = "system"

// guiDomain returns the launchd domain that holds the current user's
// LaunchAgents. A LaunchAgent belongs to a per-user GUI session, so the
// domain target carries the uid; daemons use the single system domain.
func guiDomain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
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
