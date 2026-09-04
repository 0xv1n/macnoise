package process

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

var defaultDiscoveryCommands = []string{
	"sw_vers",
	"system_profiler SPHardwareDataType",
	"system_profiler SPApplicationsDataType",
	"sysctl hw.model",
	"ifconfig",
	"whoami",
	"dscl . -list /Users",
	"csrutil status",
	"fdesetup status",
	// The three below back the T1518.001 claim and must stay in the defaults:
	// a technique claimed in Info() but only reachable by overriding params is
	// the same defect as the original T1518 claim that nothing performed.
	//
	// systemextensionsctl is the highest-signal check on modern macOS, since
	// every current EDR registers an Endpoint Security system extension, and it
	// needs no vendor list to stay current. The firewall state and the process
	// grep cover what MITRE names directly for this sub-technique.
	"systemextensionsctl list",
	"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
	// Vendor names are illustrative, not exhaustive - a miss costs one match
	// while the exec itself, which is what a detection sees, still happens.
	// Note that no pattern here may contain a comma: the commands param is
	// comma-separated, so one would split the command in half.
	//
	// The trailing || is load-bearing. grep exits 1 when it matches nothing,
	// which on a machine with no security software is the expected answer
	// rather than a failure, and without this the module reports "discovery
	// command returned error" for a probe that worked perfectly.
	`ps -eo comm= | grep -iE "crowdstrike|sentinel|falcon|littlesnitch|knockknock|jamf|defender|sophos|malwarebytes" || echo "no matching security agents"`,
}

type procDiscovery struct{}

func (p *procDiscovery) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_discovery",
		EventTypes:  []string{"system_discovery"},
		Description: "Runs macOS system reconnaissance commands, including security software enumeration, to generate discovery telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"discovery", "recon", "sysinfo", "security-software"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1082", Name: "System Information Discovery"},
			{Technique: "T1016", Name: "System Network Configuration Discovery"},
			{Technique: "T1033", Name: "System Owner/User Discovery"},
			{Technique: "T1518", Name: "Software Discovery"},
			// Backed by systemextensionsctl, socketfilterfw, and the agent
			// process grep in defaultDiscoveryCommands. MITRE names process
			// listing, application folder checks, and system extension listing
			// for this sub-technique, and cites csrutil status - already in the
			// defaults - as an XCSSET procedure for it.
			{Technique: "T1518", SubTech: ".001", Name: "Software Discovery: Security Software Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procDiscovery) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "commands",
			Description:  "Comma-separated list of discovery commands to run",
			Required:     false,
			DefaultValue: strings.Join(defaultDiscoveryCommands, ","),
			Example:      "sw_vers,whoami",
		},
	}
}

func (p *procDiscovery) CheckPrereqs() error { return nil }

func (p *procDiscovery) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	commandsParam := params.Get("commands", strings.Join(defaultDiscoveryCommands, ","))
	commands := strings.Split(commandsParam, ",")
	info := p.Info()

	for _, raw := range commands {
		cmd := strings.TrimSpace(raw)
		if cmd == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev := output.NewEvent(info, "system_discovery", false, fmt.Sprintf("running: %s", cmd))
		out, err := exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput()
		if err != nil {
			ev.Success = true
			ev.Message = fmt.Sprintf("discovery command returned error: %s", cmd)
			ev = output.WithDetails(ev, map[string]any{"command": cmd, "output": string(out), "error": err.Error()})
		} else {
			ev.Success = true
			ev.Message = fmt.Sprintf("discovery command completed: %s", cmd)
			ev = output.WithDetails(ev, map[string]any{"command": cmd, "output": string(out)})
		}
		emit(ev)
	}
	return nil
}

func (p *procDiscovery) DryRun(params module.Params) []string {
	commandsParam := params.Get("commands", strings.Join(defaultDiscoveryCommands, ","))
	commands := strings.Split(commandsParam, ",")
	steps := make([]string, 0, len(commands))
	for _, cmd := range commands {
		cmd = strings.TrimSpace(cmd)
		if cmd != "" {
			steps = append(steps, fmt.Sprintf("exec: sh -c %q", cmd))
		}
	}
	return steps
}

func (p *procDiscovery) Cleanup() error { return nil }

func init() {
	module.Register(&procDiscovery{})
}
