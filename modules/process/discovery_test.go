package process

import (
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// A MITRE technique in Info() has to be backed by something the module actually
// does with default params. proc_discovery has already shipped this defect once:
// it claimed T1518 Software Discovery while its command list contained nothing
// that enumerated software, which day 4 fixed by adding a real command rather
// than dropping the claim.
//
// This ties each discovery sub-claim to a command that performs it, so removing
// the command without removing the claim fails here rather than silently
// restoring the original defect.
func TestDiscoveryClaimsAreBackedByDefaultCommands(t *testing.T) {
	defaults := strings.Join(defaultDiscoveryCommands, "\n")

	backing := map[string][]string{
		"T1082": {"sw_vers", "system_profiler SPHardwareDataType"},
		"T1016": {"ifconfig"},
		"T1033": {"whoami"},
		"T1518": {"system_profiler SPApplicationsDataType"},
		"T1518.001": {
			"systemextensionsctl list",
			"socketfilterfw --getglobalstate",
		},
	}

	for _, m := range (&procDiscovery{}).Info().MITRE {
		id := m.Technique + m.SubTech
		cmds, ok := backing[id]
		if !ok {
			t.Errorf("%s is claimed but no backing command is recorded for it", id)
			continue
		}
		for _, cmd := range cmds {
			if !strings.Contains(defaults, cmd) {
				t.Errorf("%s is claimed but %q is not in the default commands", id, cmd)
			}
		}
	}
}

// The commands param is comma-separated, so a command containing a comma is
// silently split into two broken halves. The security-software grep pattern is
// the realistic place for one to creep in.
func TestDefaultDiscoveryCommandsContainNoCommas(t *testing.T) {
	for _, cmd := range defaultDiscoveryCommands {
		if strings.Contains(cmd, ",") {
			t.Errorf("default command would be split by the comma-separated param: %q", cmd)
		}
	}
}

// Every default command has to survive the split-and-trim round trip that
// Generate performs, or a command present in the list never runs.
func TestDefaultDiscoveryCommandsSurviveParamRoundTrip(t *testing.T) {
	joined := strings.Join(defaultDiscoveryCommands, ",")

	var got []string
	for _, raw := range strings.Split(joined, ",") {
		if cmd := strings.TrimSpace(raw); cmd != "" {
			got = append(got, cmd)
		}
	}

	if len(got) != len(defaultDiscoveryCommands) {
		t.Fatalf("round trip produced %d commands, want %d", len(got), len(defaultDiscoveryCommands))
	}
	for i, cmd := range defaultDiscoveryCommands {
		if got[i] != cmd {
			t.Errorf("command %d round-tripped to %q, want %q", i, got[i], cmd)
		}
	}
}

func TestDiscoveryDryRunListsEveryCommand(t *testing.T) {
	lines := (&procDiscovery{}).DryRun(module.Params{})
	if len(lines) != len(defaultDiscoveryCommands) {
		t.Errorf("dry run listed %d commands, want %d", len(lines), len(defaultDiscoveryCommands))
	}
}
