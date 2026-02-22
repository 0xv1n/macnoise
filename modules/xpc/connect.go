// Package xpc provides a telemetry module for XPC service enumeration via launchctl,
// generating IPC discovery activity observable by macOS security tooling.
package xpc

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type xpcConnect struct{}

func (x *xpcConnect) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "xpc_connect",
		Description: "Enumerates XPC services via launchctl and probes service availability",
		Category:    module.CategoryXPC,
		Tags:        []string{"xpc", "launchctl", "ipc", "enumeration"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1106", Name: "Native API"},
			{Technique: "T1057", Name: "Process Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (x *xpcConnect) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "filter", Description: "Filter string for service name (empty = all)", Required: false, DefaultValue: "com.apple", Example: "com.apple.security"},
		{Name: "max_results", Description: "Maximum services to enumerate", Required: false, DefaultValue: "10", Example: "20"},
	}
}

func (x *xpcConnect) CheckPrereqs() error {
	return prereqs.CheckCommand("launchctl")
}

func (x *xpcConnect) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	filter := params.Get("filter", "com.apple")
	maxStr := params.Get("max_results", "10")
	max := 10
	fmt.Sscanf(maxStr, "%d", &max) //nolint:errcheck

	info := x.Info()

	enumEv := output.NewEvent(info, "xpc_enumerate", false, "enumerating system XPC services via launchctl")
	cmd := exec.CommandContext(ctx, "launchctl", "print", "system")
	out, err := cmd.CombinedOutput()
	if err != nil {
		enumEv = output.WithError(enumEv, fmt.Errorf("launchctl print system: %v: %s", err, out))
		emit(enumEv)
		return nil
	}

	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if filter != "" && !strings.Contains(line, filter) {
			continue
		}
		if strings.Contains(line, "=") || strings.HasPrefix(line, "com.") || strings.HasPrefix(line, filter) {
			svc := strings.Fields(line)
			if len(svc) > 0 {
				services = append(services, svc[0])
			}
		}
		if len(services) >= max {
			break
		}
	}

	enumEv.Success = true
	enumEv.Message = fmt.Sprintf("enumerated %d XPC services matching %q", len(services), filter)
	enumEv = output.WithDetails(enumEv, map[string]any{
		"filter":        filter,
		"service_count": len(services),
		"services":      services,
	})
	emit(enumEv)

	return nil
}

func (x *xpcConnect) DryRun(params module.Params) []string {
	filter := params.Get("filter", "com.apple")
	return []string{
		"launchctl print system",
		fmt.Sprintf("filter services matching %q", filter),
	}
}

func (x *xpcConnect) Cleanup() error { return nil }

func init() {
	module.Register(&xpcConnect{})
}
