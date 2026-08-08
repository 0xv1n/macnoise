// Package xpc provides a telemetry module for XPC service enumeration via launchctl,
// generating IPC discovery activity observable by macOS security tooling.
package xpc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type xpcEnumerate struct{}

func (x *xpcEnumerate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "xpc_enumerate",
		Description: "Enumerates launchd service registrations via launchctl print, where XPC services are registered",
		Category:    module.CategoryXPC,
		Tags:        []string{"xpc", "launchctl", "ipc", "enumeration"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1007", Name: "System Service Discovery"},
			{Technique: "T1057", Name: "Process Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (x *xpcEnumerate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "filter", Description: "Filter string for service name (empty = all)", Required: false, DefaultValue: "com.apple", Example: "com.apple.security"},
		{Name: "max_results", Description: "Maximum services to enumerate", Required: false, DefaultValue: "10", Example: "20"},
	}
}

func (x *xpcEnumerate) CheckPrereqs() error {
	return prereqs.CheckCommand("launchctl")
}

// parseServices extracts service labels from `launchctl print <domain>` output.
//
// The services block lists one service per line as PID (or "-"), last exit
// status, then the label, so the label is the final field rather than the
// first. Taking the first field yields a PID, which is what this module used
// to record as a service name.
func parseServices(out, filter string, max int) []string {
	var services []string
	inServices := false

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)

		if !inServices {
			// The block header is "services = {", but launchctl has used
			// other spellings, so match on the leading key alone.
			if strings.HasPrefix(trimmed, "services") && strings.HasSuffix(trimmed, "{") {
				inServices = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}

		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		label := fields[len(fields)-1]
		if !strings.Contains(label, ".") {
			continue
		}
		if filter != "" && !strings.Contains(label, filter) {
			continue
		}

		services = append(services, label)
		if len(services) >= max {
			break
		}
	}
	return services
}

// enumerateDomain runs launchctl print against one domain and emits an event
// describing what it found or why it could not look.
func (x *xpcEnumerate) enumerateDomain(ctx context.Context, domain, filter string, max int, emit module.EventEmitter) {
	info := x.Info()
	ev := output.NewEvent(info, "xpc_enumerate", true, fmt.Sprintf("enumerating services in domain %s", domain))
	details := map[string]any{"domain": domain, "filter": filter}

	out, err := exec.CommandContext(ctx, "launchctl", "print", domain).CombinedOutput()
	if err != nil {
		ev = output.WithError(ev, fmt.Errorf("launchctl print %s: %v: %s", domain, err, out))
		ev.Success = true
		ev.Message = fmt.Sprintf("could not enumerate domain %s", domain)
		details["accessible"] = false
		emit(output.WithDetails(ev, details))
		return
	}

	services := parseServices(string(out), filter, max)
	ev.Message = fmt.Sprintf("enumerated %d services in %s matching %q", len(services), domain, filter)
	details["accessible"] = true
	details["service_count"] = len(services)
	details["services"] = services
	emit(output.WithDetails(ev, details))
}

func (x *xpcEnumerate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	filter := params.Get("filter", "com.apple")
	maxStr := params.Get("max_results", "10")
	max := 10
	fmt.Sscanf(maxStr, "%d", &max) //nolint:errcheck

	// The GUI domain is always enumerable by its owner, so it runs first and
	// gives an unprivileged run real data. The system domain is attempted
	// only as root: whether launchctl refuses it unprivileged is unverified,
	// and gating on euid keeps the outcome the same either way.
	x.enumerateDomain(ctx, guiDomain(), filter, max, emit)
	if os.Geteuid() == 0 {
		x.enumerateDomain(ctx, "system", filter, max, emit)
	}
	return nil
}

// guiDomain is the launchd domain holding the current user's services.
func guiDomain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func (x *xpcEnumerate) DryRun(params module.Params) []string {
	filter := params.Get("filter", "com.apple")
	actions := []string{fmt.Sprintf("launchctl print %s", guiDomain())}
	if os.Geteuid() == 0 {
		actions = append(actions, "launchctl print system")
	}
	return append(actions, fmt.Sprintf("filter service labels matching %q", filter))
}

func (x *xpcEnumerate) Cleanup() error { return nil }

func init() {
	module.Register(&xpcEnumerate{})
}
