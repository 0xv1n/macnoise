package tcc

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type tccAccessibility struct{}

func (t *tccAccessibility) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "tcc_accessibility",
		EventTypes:  []string{"tcc_accessibility_probe"},
		Description: "Probes Accessibility permission by reading UI elements via System Events",
		Category:    module.CategoryTCC,
		Tags:        []string{"tcc", "accessibility", "keylogging", "privacy"},
		Privileges:  module.PrivilegeTCC,
		MITRE: []module.MITRE{
			// Accessibility (kTCCServiceAccessibility) is the permission that
			// lets a process read other apps' UI element contents - including
			// secure text fields as they are typed - which is a keylogging
			// vector. The mapping follows tcc_fda's convention of naming the
			// technique the permission enables, not the probe itself. MITRE's
			// T1056.001 macOS examples cite event taps; the AX route is the
			// same capability by a different API.
			{Technique: "T1056", SubTech: ".001", Name: "Input Capture: Keylogging"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (t *tccAccessibility) ParamSpecs() []module.ParamSpec { return nil }

func (t *tccAccessibility) CheckPrereqs() error { return nil }

// accessibilityProbeScript reads the menu bar items of the frontmost process
// through System Events. Reading any process's UI elements requires the
// responsible app to hold Accessibility, so this returns data when granted and
// a specific authorization error when not. The menu bar is used rather than a
// window because every GUI app has one, so the probe does not depend on a
// window being open.
func accessibilityProbeScript() string {
	return `tell application "System Events" to tell (first process whose frontmost is true) to get name of every menu bar item of menu bar 1`
}

// accessibilityOutcome classifies an osascript run into an event outcome, so a
// host that refused or could not attempt the read is not reported as a broken
// tool. The discriminator is the System Events error number:
//
//   - -1719 / -25211 / "assistive access": the responsible app is not trusted
//     for Accessibility, so the read was refused. That refusal is the signal.
//   - -10810: System Events could not launch, i.e. no GUI (Aqua) session, so
//     nothing was attempted and the outcome is indeterminate.
//   - no error: the UI was read, so Accessibility is granted.
func accessibilityOutcome(err error, combinedOutput string) module.Outcome {
	if err == nil {
		return module.OutcomeExecuted
	}
	switch {
	case strings.Contains(combinedOutput, "-1719"),
		strings.Contains(combinedOutput, "-25211"),
		strings.Contains(combinedOutput, "assistive access"),
		strings.Contains(combinedOutput, "not allowed"):
		return module.OutcomeDenied
	case strings.Contains(combinedOutput, "-10810"):
		return module.OutcomeIndeterminate
	default:
		return module.OutcomeError
	}
}

func (t *tccAccessibility) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	info := t.Info()

	out, err := exec.CommandContext(ctx, "osascript", "-e", accessibilityProbeScript()).CombinedOutput()
	combined := strings.TrimSpace(string(out))
	outcome := accessibilityOutcome(err, combined)

	ev := output.NewEvent(info, "tcc_accessibility_probe", true, "probing Accessibility via System Events")
	details := map[string]any{"result": string(outcome), "method": "osascript System Events UI read"}

	switch outcome {
	case module.OutcomeExecuted:
		ev.Message = "Accessibility TCC probe: UI read succeeded, permission granted"
	case module.OutcomeDenied:
		ev.Message = "Accessibility TCC probe: read refused, permission not granted (expected without Accessibility)"
	case module.OutcomeIndeterminate:
		ev.Message = "Accessibility TCC probe: no GUI session to run System Events, no decision made"
	default:
		ev.Message = "Accessibility TCC probe: unexpected failure driving System Events"
	}

	var probeErr error
	if err != nil {
		probeErr = fmt.Errorf("osascript: %v: %s", err, combined)
	}
	ev = output.WithOutcome(ev, outcome, probeErr)
	emit(output.WithDetails(ev, details))
	return nil
}

func (t *tccAccessibility) DryRun(params module.Params) []string {
	return []string{fmt.Sprintf("osascript -e '%s' (probes Accessibility permission)", accessibilityProbeScript())}
}

func (t *tccAccessibility) Cleanup() error { return nil }

func init() {
	module.Register(&tccAccessibility{})
}
