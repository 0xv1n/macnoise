package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
)

type procGatekeeper struct {
	targetPath string
}

func (p *procGatekeeper) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "proc_gatekeeper",
		EventTypes:  []string{"test_file_create_fail", "xattr_quarantine_set", "xattr_quarantine_remove", "spctl_status_check"},
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
			Name:        "target_path",
			Description: "Path to the test file used for quarantine xattr operations",
			Type:        module.ParamPath,
			Default:     "/tmp/macnoise_gatekeeper_test",
			Example:     "/var/tmp/macnoise_gk",
		},
	}
}

func (p *procGatekeeper) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (p *procGatekeeper) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	runID := module.RunIDFromContext(ctx)
	targetPath := module.TagPath(params.String("target_path", "/tmp/macnoise_gatekeeper_test"), runID)
	p.targetPath = targetPath
	info := p.Info()

	if err := os.WriteFile(targetPath, []byte("macnoise gatekeeper test\n"), 0o644); err != nil {
		ev := output.NewEvent(info, "test_file_create_fail", module.OutcomeError, module.File(targetPath), fmt.Sprintf("failed to create test file %s", targetPath))
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}

	// The quarantine value's agent field carries the run ID so a consumer can
	// correlate the xattr back to the run.
	quarantineVal := "0081;00000000;macnoise;"
	if runID != "" {
		quarantineVal = "0081;00000000;macnoise-" + runID + ";"
	}
	setEv := output.NewEvent(info, "xattr_quarantine_set", module.OutcomeError, module.File(targetPath), fmt.Sprintf("setting quarantine xattr on %s", targetPath))
	setResult, setErr := subprocess.Run(ctx, "xattr", "-w", "com.apple.quarantine", quarantineVal, targetPath)
	if setErr != nil {
		setEv = output.WithError(setEv, fmt.Errorf("%v: %s", setErr, setResult.Output))
		if err := emit(setEv); err != nil {
			return err
		}
	} else {
		setEv.Outcome = module.OutcomeExecuted
		setEv.Message = fmt.Sprintf("set com.apple.quarantine on %s", targetPath)
		setEv = output.WithDetails(setEv, map[string]any{"path": targetPath, "action": "set", "xattr": "com.apple.quarantine"})
		if err := emit(setEv); err != nil {
			return err
		}

		rmEv := output.NewEvent(info, "xattr_quarantine_remove", module.OutcomeError, module.File(targetPath), fmt.Sprintf("removing quarantine xattr from %s", targetPath))
		rmResult, rmErr := subprocess.Run(ctx, "xattr", "-d", "com.apple.quarantine", targetPath)
		if rmErr != nil {
			rmEv = output.WithError(rmEv, fmt.Errorf("%v: %s", rmErr, rmResult.Output))
		} else {
			rmEv.Outcome = module.OutcomeExecuted
			rmEv.Message = fmt.Sprintf("removed com.apple.quarantine from %s", targetPath)
			rmEv = output.WithDetails(rmEv, map[string]any{"path": targetPath, "action": "remove", "xattr": "com.apple.quarantine"})
		}
		if err := emit(rmEv); err != nil {
			return err
		}
	}

	spctlEv := output.NewEvent(info, "spctl_status_check", module.OutcomeError, module.Process("spctl", "/usr/sbin/spctl", "spctl --status", 0), "checking Gatekeeper status via spctl --status")
	spctlResult, spctlErr := subprocess.Run(ctx, "spctl", "--status")
	if spctlErr != nil {
		spctlEv.Outcome = module.OutcomeExecuted
		spctlEv.Message = "Gatekeeper status check returned error (expected on some configs)"
		spctlEv = output.WithDetails(spctlEv, map[string]any{"output": string(spctlResult.Output), "error": spctlErr.Error()})
	} else {
		spctlEv.Outcome = module.OutcomeExecuted
		spctlEv.Message = fmt.Sprintf("Gatekeeper status: %s", strings.TrimSpace(string(spctlResult.Output)))
		spctlEv = output.WithDetails(spctlEv, map[string]any{"output": string(spctlResult.Output)})
	}
	return emit(spctlEv)
}

func (p *procGatekeeper) DryRun(params module.Params) []string {
	targetPath := params.String("target_path", "/tmp/macnoise_gatekeeper_test")
	return []string{
		fmt.Sprintf("create test file at %s", targetPath),
		fmt.Sprintf("xattr -w com.apple.quarantine 0081;00000000;macnoise; %s", targetPath),
		fmt.Sprintf("xattr -d com.apple.quarantine %s", targetPath),
		"spctl --status",
	}
}

func (p *procGatekeeper) Cleanup(ctx context.Context) error {
	if p.targetPath != "" {
		if err := os.Remove(p.targetPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func init() {
	module.Register(func() module.Generator { return &procGatekeeper{} })
}
