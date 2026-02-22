package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procGatekeeper struct {
	targetPath string
}

func (p *procGatekeeper) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_gatekeeper",
		Description: "Sets and removes com.apple.quarantine xattr to simulate Gatekeeper bypass telemetry",
		Category:    module.CategoryProcess,
		Tags:        []string{"gatekeeper", "quarantine", "xattr", "bypass"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1553", SubTech: ".001", Name: "Subvert Trust Controls: Gatekeeper Bypass"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (p *procGatekeeper) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "target_path",
			Description:  "Path to the test file used for quarantine xattr operations",
			Required:     false,
			DefaultValue: "/tmp/macnoise_gatekeeper_test",
			Example:      "/var/tmp/macnoise_gk",
		},
	}
}

func (p *procGatekeeper) CheckPrereqs() error { return nil }

func (p *procGatekeeper) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	targetPath := params.Get("target_path", "/tmp/macnoise_gatekeeper_test")
	p.targetPath = targetPath
	info := p.Info()

	if err := os.WriteFile(targetPath, []byte("macnoise gatekeeper test\n"), 0o644); err != nil {
		ev := output.NewEvent(info, "xattr_quarantine_remove", false, fmt.Sprintf("failed to create test file %s", targetPath))
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}

	setEv := output.NewEvent(info, "xattr_quarantine_remove", false, fmt.Sprintf("setting quarantine xattr on %s", targetPath))
	setOut, setErr := exec.CommandContext(ctx, "xattr", "-w", "com.apple.quarantine", "0081;00000000;macnoise;", targetPath).CombinedOutput()
	if setErr != nil {
		setEv = output.WithError(setEv, fmt.Errorf("%v: %s", setErr, setOut))
		emit(setEv)
	} else {
		setEv.Success = true
		setEv.Message = fmt.Sprintf("set com.apple.quarantine on %s", targetPath)
		setEv = output.WithDetails(setEv, map[string]any{"path": targetPath, "action": "set", "xattr": "com.apple.quarantine"})
		emit(setEv)

		rmEv := output.NewEvent(info, "xattr_quarantine_remove", false, fmt.Sprintf("removing quarantine xattr from %s", targetPath))
		rmOut, rmErr := exec.CommandContext(ctx, "xattr", "-d", "com.apple.quarantine", targetPath).CombinedOutput()
		if rmErr != nil {
			rmEv = output.WithError(rmEv, fmt.Errorf("%v: %s", rmErr, rmOut))
		} else {
			rmEv.Success = true
			rmEv.Message = fmt.Sprintf("removed com.apple.quarantine from %s", targetPath)
			rmEv = output.WithDetails(rmEv, map[string]any{"path": targetPath, "action": "remove", "xattr": "com.apple.quarantine"})
		}
		emit(rmEv)
	}

	spctlEv := output.NewEvent(info, "spctl_status_check", false, "checking Gatekeeper status via spctl --status")
	spctlOut, spctlErr := exec.CommandContext(ctx, "spctl", "--status").CombinedOutput()
	if spctlErr != nil {
		spctlEv.Success = true
		spctlEv.Message = "Gatekeeper status check returned error (expected on some configs)"
		spctlEv = output.WithDetails(spctlEv, map[string]any{"output": string(spctlOut), "error": spctlErr.Error()})
	} else {
		spctlEv.Success = true
		spctlEv.Message = fmt.Sprintf("Gatekeeper status: %s", strings.TrimSpace(string(spctlOut)))
		spctlEv = output.WithDetails(spctlEv, map[string]any{"output": string(spctlOut)})
	}
	emit(spctlEv)

	return nil
}

func (p *procGatekeeper) DryRun(params module.Params) []string {
	targetPath := params.Get("target_path", "/tmp/macnoise_gatekeeper_test")
	return []string{
		fmt.Sprintf("create test file at %s", targetPath),
		fmt.Sprintf("xattr -w com.apple.quarantine 0081;00000000;macnoise; %s", targetPath),
		fmt.Sprintf("xattr -d com.apple.quarantine %s", targetPath),
		"spctl --status",
	}
}

func (p *procGatekeeper) Cleanup() error {
	if p.targetPath != "" {
		if err := os.Remove(p.targetPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func init() {
	module.Register(&procGatekeeper{})
}
